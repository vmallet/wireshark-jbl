/* packet-jbl.c
 * Dissector for JBL/Harman Soundbar's on-device protocol.
 * Copyright 2021, Vincent Mallet <vmallet@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998, Gerald Combs.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <stdio.h>

#include <epan/packet.h>
#include <epan/conversation.h>

#include <epan/dissectors/packet-tcp.h>

#include "msgpack.h"

#define JBL_PORT 9999

static int proto_jbl = -1;

static int hf_jbl_handshake = -1;

static int hf_jbl_type = -1;
static int hf_jbl_call_type = -1;
static int hf_jbl_len = -1;
static int hf_jbl_multi_pdu = -1;
static int hf_jbl_msg_data_short = -1;
static int hf_jbl_msg_data_full = -1;
static int hf_jbl_seq_num = -1;
static int hf_jbl_event_name = -1;
static int hf_jbl_event_id = -1;
static int hf_jbl_sub_id = -1;
static int hf_jbl_rpc_name = -1;
static int hf_jbl_rpc_id = -1;
static int hf_jbl_error = -1;

static int hf_jbl_kwargs = -1;
static int hf_jbl_kwarg_key = -1;
static int hf_jbl_kwarg_val = -1;
static int hf_jbl_kwarg_thread_id = -1;
static int hf_jbl_kwarg_state = -1;
static int hf_jbl_kwarg_service = -1;
static int hf_jbl_kwarg_dis_mode = -1;
static int hf_jbl_kwarg_dis_time = -1;
static int hf_jbl_kwarg_dis_mand = -1;
static int hf_jbl_kwarg_action = -1;
static int hf_jbl_kwarg_player = -1;
static int hf_jbl_kwarg_nextsrc = -1;
static int hf_jbl_kwarg_level = -1;
static int hf_jbl_kwarg_timeout = -1;

static int hf_jbl_args = -1;
static int hf_jbl_arg_int = -1;
static int hf_jbl_arg_bool = -1;
static int hf_jbl_arg_str = -1;
static int hf_jbl_arg_other = -1;

static gint ett_jbl = -1;


static GHashTable *jbl_params = NULL;

#define JBL_HANDSHAKE_MAGIC  0x7FF20000

/* Minimum PDU length: handshake (4 bytes) or PDU length (4 bytes)*/
#define JBL_MINIMUM_PDU_LENGTH 4

#define JBL_MSG_HELLO           1
#define JBL_MSG_WELCOME         2
#define JBL_MSG_ABORT           3
#define JBL_MSG_CHALLENGE       4
#define JBL_MSG_AUTHENTICATE    5
#define JBL_MSG_GOODBYE         6
#define JBL_MSG_HEARBEAT        7
#define JBL_MSG_ERROR           8
#define JBL_MSG_PUBLISH        16
#define JBL_MSG_PUBLISHED      17
#define JBL_MSG_SUBSCRIBE      32
#define JBL_MSG_SUBSCRIBED     33
#define JBL_MSG_UNSUBSCRIBE    34
#define JBL_MSG_UNSUBSCRIBED   35
#define JBL_MSG_EVENT          36
#define JBL_MSG_CALL           48
#define JBL_MSG_CANCEL         49
#define JBL_MSG_CALL_RESULT    50
#define JBL_MSG_REGISTER_RPC   64
#define JBL_MSG_REGISTERED_RPC 65
#define JBL_MSG_UNREGISTER     66
#define JBL_MSG_UNREGISTERED   67
#define JBL_MSG_INVOKE_RPC     68
#define JBL_MSG_INTERRUPT      69
#define JBL_MSG_INVOKE_YIELD   70


static const value_string type_names[] = {
    { JBL_MSG_HELLO          , "Hello" },
    { JBL_MSG_WELCOME        , "Welcome" },
    { JBL_MSG_ABORT          , "Abort" },
    { JBL_MSG_CHALLENGE      , "Challenge" },
    { JBL_MSG_AUTHENTICATE   , "Authenticate" },
    { JBL_MSG_GOODBYE        , "Goodbye" },
    { JBL_MSG_HEARBEAT       , "Heartbeat" },
    { JBL_MSG_ERROR          , "Error" },
    { JBL_MSG_PUBLISH        , "Publish" },
    { JBL_MSG_PUBLISHED      , "Published" },
    { JBL_MSG_SUBSCRIBE      , "Subscribe" },
    { JBL_MSG_SUBSCRIBED     , "Subscribed" },
    { JBL_MSG_UNSUBSCRIBE    , "Unsubscribe" },
    { JBL_MSG_UNSUBSCRIBED   , "Unsubscribed" },
    { JBL_MSG_EVENT          , "Event" },
    { JBL_MSG_CALL           , "Call" },
    { JBL_MSG_CANCEL         , "Cancel" },
    { JBL_MSG_CALL_RESULT    , "CallResult" },
    { JBL_MSG_REGISTER_RPC   , "Register" },
    { JBL_MSG_REGISTERED_RPC , "Registered" },
    { JBL_MSG_UNREGISTER     , "Unregister" },
    { JBL_MSG_UNREGISTERED   , "Unregistered" },
    { JBL_MSG_INVOKE_RPC     , "Invoke" },
    { JBL_MSG_INTERRUPT      , "Interrupt" },
    { JBL_MSG_INVOKE_YIELD   , "Yield" },
    { 0, "NULL" }
};

/* Desegmentation of JBL messages over TCP */
static gboolean jbl_desegment = TRUE;

/* Abbreviate com.harman. to c.h.  */
static gboolean jbl_abbreviate = TRUE;

/* Whether or not to resolve seq_num -> rpc_name for CallResult / Yield */
static gboolean jbl_resolve_calls = TRUE;

static struct _info_builder {
    char * buf;
    int size;
    char *cur;
} info_builder = {
    NULL, 0, NULL
};


typedef struct _jbl_conv_data {
    wmem_map_t *strings; // str -> str string interning map
    wmem_map_t *sub_reqs; // seq_num -> event_name
    wmem_map_t *subs; // sub_id -> event_name
    wmem_map_t *rpc_reqs; // seq_num -> rpc_name
    wmem_map_t *rpcs; // rpc_id -> rpc_name
    wmem_map_t *calls; // seq_num -> rpc_name
    wmem_map_t *invokes; // seq_num -> rpc_name
} jbl_conv_data_t;



#define MAX_TEMP_STR_SIZE 2048

static const char * get_object_str(msgpack_object *obj) {
    char *buf;
    if (obj->type == MSGPACK_OBJECT_STR) {
        int size = obj->via.str.size;
        buf = wmem_alloc(wmem_packet_scope(), size + 1);
        memcpy(buf, obj->via.str.ptr, size);
        buf[size] = '\0';
        return buf;
    }
    buf = wmem_alloc(wmem_packet_scope(), MAX_TEMP_STR_SIZE);
    msgpack_object_print_buffer(buf, MAX_TEMP_STR_SIZE, *obj);
    buf[MAX_TEMP_STR_SIZE - 1] = '\0';
    
    return buf;
}



static void info_builder_init(struct _info_builder *builder,  int size) {
    if (builder->buf) {
        wmem_free(wmem_packet_scope(), builder->buf);
    }
    builder->buf = wmem_alloc(wmem_packet_scope(), size + 1); // +1: safe NUL-termination
    *builder->buf = '\0';
    builder->size = size;
    builder->cur = builder->buf;
}

static void info_builder_append_max(struct _info_builder *builder, const char *s, int maxlen) {
    //TODO: check_init(builder);
    int left = builder->size - (int) (builder->cur - builder->buf);
    int copy_len = (int) strlen(s);
    if (maxlen < copy_len) {
        copy_len = maxlen;
    }
    if (left < copy_len) {
        copy_len = left;
    }
    strncpy(builder->cur, s, copy_len);
    builder->cur += copy_len;
    *builder->cur = '\0';
}

static void info_builder_append(struct _info_builder *builder, const char *s) {
    //TODO: check_init(builder);
    info_builder_append_max(builder, s, builder->size);
}


#define JBL_BUILDER_NUM_TMP_BUF 32
#define JBL_BUILDER_NUM_ABBREV_SUB "..."

static void info_builder_append_num_abbrev(struct _info_builder *builder, guint64 num,
                                           int max_len) {
    static const int abbrev_len = strlen(JBL_BUILDER_NUM_ABBREV_SUB);

    char buf[JBL_BUILDER_NUM_TMP_BUF];
    snprintf(buf, JBL_BUILDER_NUM_TMP_BUF, "%llu", num);
    buf[JBL_BUILDER_NUM_TMP_BUF - 1] = '\0';
    char *p = buf;
    int len = (int) strlen(buf);
    if (max_len > 0 && max_len > abbrev_len && len > (max_len - abbrev_len)) {
        p = &buf[len - max_len];
        memcpy(p, JBL_BUILDER_NUM_ABBREV_SUB, abbrev_len);
    }
    //TODO: check_init(builder);
    info_builder_append(builder, p);
}

static void info_builder_append_num(struct _info_builder *builder, guint64 num) {
    info_builder_append_num_abbrev(builder, num, 0);
}



#define JBL_STR_ABBREV_PREFIX   "com.harman."
#define JBL_STR_ABBREV_SUB      "c.h."

/* Shortens "com.harman." leading string as "c.h." */
static void info_builder_append_abbrev_max(struct _info_builder *builder, const char *s,
                                           int max_len) {
    static const int prefix_len = strlen(JBL_STR_ABBREV_PREFIX);
    static const int sub_len = strlen(JBL_STR_ABBREV_SUB);

    int max = max_len;
    const char *p = s;
    if (jbl_abbreviate && 0 == strncmp(s, JBL_STR_ABBREV_PREFIX, prefix_len)) {
        info_builder_append_max(builder, JBL_STR_ABBREV_SUB, max);
        max -= sub_len;
        p += prefix_len;
    }
    info_builder_append_max(builder, p, max);
}

static void info_builder_append_obj(struct _info_builder *builder, msgpack_object *obj) {
    const char *str = get_object_str(obj);
    info_builder_append(builder, str);
}



#define MSGPACK_MEMPOOL_SIZE 4096
#define STR_SIZE 2048

#define MAX_INFO_SIZE 256


void print(char const* buf,size_t len) {
    size_t i = 0;
    for(; i < len ; ++i) {
        printf("%02x ", 0xff & buf[i]);
    }
    printf("\n");
}




static void init_param_table() {
    jbl_params = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(jbl_params, "thread_id", &hf_jbl_kwarg_thread_id);
    g_hash_table_insert(jbl_params, "service", &hf_jbl_kwarg_service);
    g_hash_table_insert(jbl_params, "state", &hf_jbl_kwarg_state);
    g_hash_table_insert(jbl_params, "dis_mode", &hf_jbl_kwarg_dis_mode);
    g_hash_table_insert(jbl_params, "dis_time", &hf_jbl_kwarg_dis_time);
    g_hash_table_insert(jbl_params, "dis_mand", &hf_jbl_kwarg_dis_mand);
    g_hash_table_insert(jbl_params, "action", &hf_jbl_kwarg_action);
    g_hash_table_insert(jbl_params, "player", &hf_jbl_kwarg_player);
    g_hash_table_insert(jbl_params, "nextsrc", &hf_jbl_kwarg_nextsrc);
    g_hash_table_insert(jbl_params, "level", &hf_jbl_kwarg_level);
    g_hash_table_insert(jbl_params, "timeout", &hf_jbl_kwarg_timeout);
}


#define INFO_BUILDER_SIZE 512

static void reset_state() {
    info_builder_init(&info_builder, INFO_BUILDER_SIZE);
}

static void error(char *msg) { //TODO: do something useful
    fprintf(stderr, "%s\n", msg);
}

static gint64 * make_durable_key_int64(gint64 key_val) {
    gint64 * key = wmem_alloc(wmem_file_scope(), sizeof(gint64));
    *key = key_val;
    return key;
}

//TODO: ideally find a way to intern at the "file" scope, not the conversation scope
static const char * jbl_intern_string(jbl_conv_data_t *data, const char *s) {
    const char * interned = wmem_map_lookup(data->strings, s);
    if (interned == NULL) {
        interned = wmem_strdup(wmem_file_scope(), s);
        wmem_map_insert(data->strings, interned, (void *) interned);
    }
    return interned;
}

static void init_conv_data(jbl_conv_data_t *data) {
    //TODO: it would be great to have strings tied to a file, not a specific conversation
    data->strings = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
    data->sub_reqs = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    data->subs = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    data->rpc_reqs = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    data->rpcs = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    data->calls = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    data->invokes = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
}

static jbl_conv_data_t * get_or_create_conv_data(packet_info *pinfo) {
    conversation_t *conversation;
    jbl_conv_data_t *data;
    
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
            pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    
    if (!conversation) {
        conversation = conversation_new(pinfo->num,  &pinfo->src, &pinfo->dst, pinfo->ptype,
            pinfo->srcport, pinfo->destport, 0);
    }
    
    data = (jbl_conv_data_t *) conversation_get_proto_data(conversation, proto_jbl);
    if (!data) {
        data = wmem_alloc(wmem_file_scope(), sizeof(jbl_conv_data_t));
        init_conv_data(data);

        conversation_add_proto_data(conversation, proto_jbl, data);
    }

    return data;
}


static int process_args(proto_tree *jbl, int offset, msgpack_object *p_next, tvbuff_t *tvb) {
    msgpack_object *args = p_next;
    if (args->type != MSGPACK_OBJECT_ARRAY) {
        error("Args should be ARRAY");
        return 1;
    }

    guint args_size = (guint) args->via.u64;
    proto_item *item3 = proto_tree_add_uint(jbl, hf_jbl_args, tvb, offset, 0, args_size);
    msgpack_object * ap = args->via.array.ptr;
    msgpack_object * const apend = args->via.array.ptr + args_size;
    if (args_size == 0) {
        proto_item_append_text(item3, " (empty)");
    } else {
        info_builder_append(&info_builder, " ");
        info_builder_append_obj(&info_builder, p_next);
        proto_tree * targs = proto_item_add_subtree(item3, ett_jbl);
        for (; ap < apend; ++ap) {
            switch (ap->type) {
                case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                    proto_tree_add_int64(targs, hf_jbl_arg_int, tvb, offset, 0, ap->via.i64);
                    break;
                case MSGPACK_OBJECT_POSITIVE_INTEGER:
                    proto_tree_add_int64(targs, hf_jbl_arg_int, tvb, offset, 0, ap->via.u64);
                    break;
                case MSGPACK_OBJECT_BOOLEAN:
                    proto_tree_add_boolean(targs, hf_jbl_arg_bool, tvb, offset, 0, ap->via.boolean);
                    break;
                case MSGPACK_OBJECT_STR:
                    proto_tree_add_string(targs, hf_jbl_arg_str, tvb, offset, 0, get_object_str(ap));
                    break;
                default:
                    proto_tree_add_string(targs, hf_jbl_arg_other, tvb, offset, 0, get_object_str(ap));
                    break;
            }
        }
    }

    return 0;
}

static int process_kwargs(proto_tree *jbl, int offset, msgpack_object *p_next, tvbuff_t *tvb) {
    msgpack_object *kwargs = p_next;
    if (kwargs->type != MSGPACK_OBJECT_MAP) {
        error("kwargs should be MAP");
        return 1;
    }

    guint kwargs_size = (guint) kwargs->via.u64;
    proto_item *item2 = proto_tree_add_uint(jbl, hf_jbl_kwargs, tvb, offset, 0, kwargs_size);
    msgpack_object_kv* kvp = kwargs->via.map.ptr;
    msgpack_object_kv* const kvpend = kwargs->via.map.ptr + kwargs_size;
    if (kwargs_size == 0) {
        proto_item_append_text(item2, " (empty)");
    } else {
        proto_tree * sub = proto_item_add_subtree(item2, ett_jbl);
        for (; kvp < kvpend; ++kvp) {
            const char * key = get_object_str(&kvp->key);
            int *hf_param = g_hash_table_lookup(jbl_params, key);
            if (hf_param) {
                //TODO: decide type based on hf_param, not wire type. For now need something that runs
                switch (kvp->val.type) {
                    case MSGPACK_OBJECT_POSITIVE_INTEGER:
                        proto_tree_add_uint64(sub, *hf_param, tvb, offset, 0, kvp->val.via.u64);
                        break;
                    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                        proto_tree_add_int64(sub, *hf_param, tvb, offset, 0, kvp->val.via.i64);
                        break;
                    default:
                        proto_tree_add_string(sub, *hf_param, tvb, offset, 0, get_object_str(&kvp->val));
                        break;
                }
            } else {
                proto_item * key_it = proto_tree_add_string(sub, hf_jbl_kwarg_key, tvb, offset, 0, get_object_str(&kvp->key));
                proto_tree * key_sub = proto_item_add_subtree(key_it, ett_jbl);
                proto_tree_add_string(key_sub, hf_jbl_kwarg_val, tvb, offset, 0, get_object_str(&kvp->val));
            }
        }
        info_builder_append(&info_builder, " ");
        info_builder_append_max(&info_builder, get_object_str(kwargs), 128);
    }
    return 0;
}

static int decode_msg_publish(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                              proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    
    // [16, 13, {}, "com.harman.test.inputEvent", ["ir-volumeup", "1"]]
    // [16, 187003, {}, "com.harman.music.stateChanged", ["com.harman.HDMI"], {"service"=>"HDMI", "state"=>"paused"}]
    if ((p_end - p_next) < 3) {
        //TODO: include err in info?
        error("Protocol error: publish needs 2 args at least");
        return 1;
    }
    
    // Seq number
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: publish arg 2 should be an int");
        return 1;
    }
    
    guint64 num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, num);
                            

    // Empty map
    p_next++;
    // TODO: figure out what it is


    // event name
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("Event name should be string");
        return 1;
    }
    const char *event_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_event_name, tvb, offset, 0, event_name);
    info_builder_append_abbrev_max(&info_builder, event_name, 48);

    
    // event args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_args(jbl, offset, p_next, tvb)) {
        return 1;
    }

    
    // Event kwargs
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_kwargs(jbl, offset, p_next, tvb)) {
        return 1;
    }

    return 0;
}

static int decode_msg_event(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                            proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [36, 10, 4588522949814990, {}, ["ir-power", "0"]]
    if ((p_end - p_next) < 4) {
        //TODO: include err in info?
        info_builder_append(&info_builder, "Not enough arguments, needed at least 5, got: ");
        info_builder_append_num(&info_builder, (int) (p_end - p_next));;
        error("Protocol error: Event needs 5 args at least");
        return 1;
    }

    // sub_id
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Event arg 2 (Sub Id) should be an int");
        return 1;
    }

    guint64 sub_id = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_sub_id, tvb, offset, 0, sub_id);

    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    char * event_name = wmem_map_lookup(data->subs, &sub_id);
    if (!event_name) {
        info_builder_append(&info_builder, "SubId=");
        info_builder_append_num(&info_builder, sub_id);
    } else {
        proto_tree_add_string(jbl, hf_jbl_event_name, tvb, offset, 0, event_name);
        info_builder_append_abbrev_max(&info_builder, event_name, 48);
    }

    // event_id
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Event arg 3 should be an int");
        return 1;
    }

    guint64 event_id = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_event_id, tvb, offset, 0, event_id);
    info_builder_append(&info_builder, " Id=");
    info_builder_append_num_abbrev(&info_builder, event_id, 7);


    // Empty map
    p_next++;
    // TODO: figure out what it is


    // Event args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_args(jbl, offset, p_next, tvb)) {
        return 1;
    }

    // Event kwargs
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_kwargs(jbl, offset, p_next, tvb)) {
        return 1;
    }

    return 0;
}

static int decode_msg_subscribe(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                                proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [32, 9, {}, "com.harman.powerModeChanged"]
    if ((p_end - p_next) < 3) {
        //TODO: include err in info?
        info_builder_append(&info_builder, "Not enough arguments, needed at least 3, got: ");
        info_builder_append_num(&info_builder, (int) (p_end - p_next));;
        error("Protocol error: subscribe needs 3 args");
        return 1;
    }
    
    // seq_num
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: subscribe arg 2 should be an int");
        return 1;
    }
    
    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);

    // Empty map
    p_next++;
    // TODO: figure out what it is

    // event name
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("Event name should be STR");
        return 1;
    }
    const char *event_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_event_name, tvb, offset, 0, event_name);
    info_builder_append_abbrev_max(&info_builder, event_name, 48);
    
    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    gint64 *key = make_durable_key_int64(seq_num);
    const char *durable_name = jbl_intern_string(data, event_name);
    wmem_map_insert(data->sub_reqs, key, (void *) durable_name);
    return 0;
}

static int decode_msg_subscribed(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                                 proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [33, 9, 118]
    if ((p_end - p_next) < 2) {
        //TODO: include err in info?
        info_builder_append(&info_builder, "Not enough arguments, needed at least 2, got: ");
        info_builder_append_num(&info_builder, (int) (p_end - p_next));;
        error("Protocol error: subscribed needs 3 args");
        return 1;
    }
    
    // seq_num
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: subscribed arg 2 should be an int");
        return 1;
    }
    
    gint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);

    // sub_id
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: publish arg 2 should be an int");
        return 1;
    }
    
    guint64 sub_id = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_sub_id, tvb, offset, 0, sub_id);

    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    char * event_name = wmem_map_lookup(data->sub_reqs, &seq_num);
    if (event_name) {
        gint64 *key = make_durable_key_int64(sub_id);
        wmem_map_insert(data->subs, key, event_name);
        info_builder_append_abbrev_max(&info_builder, event_name, 48);
        proto_item * evt_item = proto_tree_add_string(jbl, hf_jbl_event_name, tvb, offset, 0, event_name);
        proto_item_set_generated(evt_item);
    } else {
        info_builder_append_num(&info_builder, seq_num);
    }
    info_builder_append(&info_builder, " => ");
    info_builder_append_num(&info_builder, sub_id);

    return 0;
}

static int decode_msg_register(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                               proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [64, 5, {}, "com.harman.lcdis.source"]
    if ((p_end - p_next) < 3) {
        //TODO: include err in info?
        info_builder_append(&info_builder, "Not enough arguments, needed at least 3, got: ");
        info_builder_append_num(&info_builder, (int) (p_end - p_next));;
        error("Protocol error: Register needs 3 args");
        return 1;
    }

    // seq_num
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Register arg 2 (Seq Num) should be an int");
        return 1;
    }

    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);

    // Empty map
    p_next++;
    // TODO: figure out what it is

    // RPC name
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("RPC name should be STR");
        return 1;
    }
    const char *rpc_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_rpc_name, tvb, offset, 0, rpc_name);
    info_builder_append_abbrev_max(&info_builder, rpc_name, 48);

    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    gint64 *key = make_durable_key_int64(seq_num);
    const char *durable_name = jbl_intern_string(data, rpc_name);
    wmem_map_insert(data->rpc_reqs, key, (void *) durable_name);
    return 0;
}

static int decode_msg_registered(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                                 proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [65, 5, 406]
    if ((p_end - p_next) < 2) {
        //TODO: include err in info?
        info_builder_append(&info_builder, "Not enough arguments, needed at least 2, got: ");
        info_builder_append_num(&info_builder, (int) (p_end - p_next));;
        error("Protocol error: Registered needs 3 args");
        return 1;
    }

    // seq_num
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Registered arg 2 should be an int");
        return 1;
    }

    gint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);

    // rpc_id
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: RPC Id (Registered arg 2) should be an int");
        return 1;
    }

    gint64 rpc_id = p_next->via.i64;
    proto_tree_add_uint64(jbl, hf_jbl_rpc_id, tvb, offset, 0, rpc_id);

    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    char * rpc_name = wmem_map_lookup(data->rpc_reqs, &seq_num);
    if (rpc_name) {
        gint64 *key = make_durable_key_int64(rpc_id);
        wmem_map_insert(data->rpcs, key, rpc_name);
        info_builder_append_abbrev_max(&info_builder, rpc_name, 48);
        proto_item * rpc_item = proto_tree_add_string(jbl, hf_jbl_rpc_name, tvb, offset, 0, rpc_name);
        proto_item_set_generated(rpc_item);
    } else {
        info_builder_append_num(&info_builder, seq_num);
    }
    info_builder_append(&info_builder, " => ");
    info_builder_append_num(&info_builder, rpc_id);

    return 0;
}

static int decode_msg_call(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                             proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {

    // [48, 186888, {}, "com.harman.lcdMode", [1]]
    // [48, 75, {}, "com.harman.source.get-active", []]
    // [48, 671, {}, "com.harman.aui.playerPreAction", ["com.harman.HDMI"], {"action"=>"playing"}]

    if ((p_end - p_next) < 3) {
        //TODO: include err in info?
        error("Protocol error: Invoke needs 2 args at least");
        return 1;
    }


    // Seq number
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Invoke arg 2 should be an int");
        return 1;
    }

    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);


    // Empty map
    p_next++;
    // TODO: figure out what it is


    // RPC name
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("RPC name should be STR");
        return 1;
    }
    const char *rpc_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_rpc_name, tvb, offset, 0, rpc_name);
    info_builder_append_abbrev_max(&info_builder, rpc_name, 48);

    if (jbl_resolve_calls) {
        jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
        gint64 *key = make_durable_key_int64(seq_num);
        const char *durable_name = jbl_intern_string(data, rpc_name);
        wmem_map_insert(data->calls, key, (void *) durable_name);
    }


    // Call args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_args(jbl, offset, p_next, tvb)) {
        return 1;
    }


    // Call kwargs
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_kwargs(jbl, offset, p_next, tvb)) {
        return 1;
    }

    return 0;
}

static int decode_msg_call_result(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                                  proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [50, 274, {}, ["com.harman.idle"]]
    // [50, 666, {}, [], {"music"=>{"hotel_max_vol"=>32, "mute"=>0, "volume"=>11}}]
    // [50, 67, {}, [true]]
    // [50, 669, {}]
    // [50, 187000, {}, [0]]
    // [50, 187865, {}, [true, "music"], {"music"=>{"hotel_max_vol"=>32, "mute"=>1, "volume"=>11}}]

    if ((p_end - p_next) < 2) {
        //TODO: include err in info?
        error("Protocol error: Call Result needs 2 args at least");
        return 1;
    }
    
    // Seq number
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Call Result arg 2 should be an int");
        return 1;
    }
    
    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);

    char *rpc_name = NULL;
    if (jbl_resolve_calls) {
        jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
        rpc_name = wmem_map_lookup(data->calls, &seq_num);
    }

    if (rpc_name != NULL) {
        info_builder_append_abbrev_max(&info_builder, rpc_name, 48);
        proto_item * rpc_item = proto_tree_add_string(jbl, hf_jbl_rpc_name, tvb, offset, 0, rpc_name);
        proto_item_set_generated(rpc_item);
    } else {
        info_builder_append(&info_builder, "Seq=");
        info_builder_append_num(&info_builder, seq_num);
    }
    info_builder_append(&info_builder, " =>");


    // Empty map
    p_next++;
    // TODO: figure out what it is


    // Call Result Args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_args(jbl, offset, p_next, tvb)) {
        return 1;
    }

    
    // Call Result kwargs
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_kwargs(jbl, offset, p_next, tvb)) {
        return 1;
    }

    return 0;
}

static int decode_msg_invoke(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                             proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {

    // [68, 2058, 84, {}, ["com.harman.HDMI"]]
    // [68, 2070, 82, {}, ["com.harman.HDMI"], {"service"=>"HDMI", "state"=>"paused"}]
    // [68, 2074, 404, {}, ["vol12"], {"dis_mode"=>0, "dis_time"=>5}]

    if ((p_end - p_next) < 3) {
        //TODO: include err in info?
        error("Protocol error: Invoke needs 2 args at least");
        return 1;
    }

    // Seq number
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Invoke arg 2 should be an int");
        return 1;
    }

    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);


    // rpc_id
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Invoke arg 3 (RPC Id) should be an int");
        return 1;
    }

    guint64 rpc_id = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_rpc_id, tvb, offset, 0, rpc_id);

    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    char * rpc_name = wmem_map_lookup(data->rpcs, &rpc_id);
    if (rpc_name) {
        info_builder_append_abbrev_max(&info_builder, rpc_name, 48);
        proto_item * rpc_item = proto_tree_add_string(jbl, hf_jbl_rpc_name, tvb, offset, 0, rpc_name);
        proto_item_set_generated(rpc_item);
    } else {
        info_builder_append(&info_builder, "RpcId=");
        info_builder_append_num(&info_builder, rpc_id);
    }

    if (jbl_resolve_calls && rpc_name != NULL) {
        gint64 *key = make_durable_key_int64(seq_num);
        // Note: rpc_name came from our lookup, it's already interned
        wmem_map_insert(data->invokes, key, (void *) rpc_name);
    }


    // Empty map
    p_next++;
    // TODO: figure out what it is


    // Invoke args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_args(jbl, offset, p_next, tvb)) {
        return 1;
    }


    // Invoke kwargs
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_kwargs(jbl, offset, p_next, tvb)) {
        return 1;
    }

    return 0;
}

static int decode_msg_yield(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                            proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [70, 2143, {}]
    // [70, 2127, {}, [true]]
    // [70, 2135, {}, [true, "music"], {"music"=>{"hotel_max_vol"=>32, "mute"=>1, "volume"=>11}}]
    // [70, 2149, {}, ["com.harman.idle"]]

    if ((p_end - p_next) < 2) {
        //TODO: include err in info?
        error("Protocol error: Yield needs 2 args at least");
        return 1;
    }

    // Seq number
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Yield arg 2 should be an int");
        return 1;
    }

    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);

    char *rpc_name = NULL;
    if (jbl_resolve_calls) {
        jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
        rpc_name = wmem_map_lookup(data->invokes, &seq_num);
    }

    if (rpc_name != NULL) {
        info_builder_append_abbrev_max(&info_builder, rpc_name, 48);
        proto_item * rpc_item = proto_tree_add_string(jbl, hf_jbl_rpc_name, tvb, offset, 0, rpc_name);
        proto_item_set_generated(rpc_item);
    } else {
        info_builder_append(&info_builder, "Seq=");
        info_builder_append_num(&info_builder, seq_num);
    }
    info_builder_append(&info_builder, " =>");


    // Empty map
    p_next++;
    // TODO: figure out what it is


    // Yield Args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_args(jbl, offset, p_next, tvb)) {
        return 1;
    }


    // Yield kwargs
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    if (process_kwargs(jbl, offset, p_next, tvb)) {
        return 1;
    }

    return 0;
}

static int decode_msg_error(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                            proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [8, 48, 15, {}, "wamp.error.no_such_procedure"]

    if ((p_end - p_next) < 3) {
        //TODO: include err in info?
        error("Protocol error: Error needs 3 args at least");
        return 1;
    }

    // Call type
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Error arg 3 should be an int");
        return 1;
    }

    guint call_type = (guint) p_next->via.u64;
    proto_tree_add_uint(jbl, hf_jbl_call_type, tvb, offset, 0, call_type);


    // Seq number
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: Error arg 2 should be an int");
        return 1;
    }

    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);

    char *rpc_name = NULL;
    if (jbl_resolve_calls) {
        jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
        switch (call_type) {
            case JBL_MSG_CALL:
                rpc_name = wmem_map_lookup(data->calls, &seq_num);
                break;
            case JBL_MSG_INVOKE_RPC:
                rpc_name = wmem_map_lookup(data->invokes, &seq_num);
                break;
            default:
                // TODO: we could consider logging this; what other type could it be?
                break;
        }
    }

    if (rpc_name != NULL) {
        info_builder_append_abbrev_max(&info_builder, rpc_name, 48);
        proto_item * rpc_item = proto_tree_add_string(jbl, hf_jbl_rpc_name, tvb, offset, 0, rpc_name);
        proto_item_set_generated(rpc_item);
    } else {
        info_builder_append(&info_builder, "Seq=");
        info_builder_append_num(&info_builder, seq_num);
    }
    info_builder_append(&info_builder, " (");
    info_builder_append(&info_builder, val_to_str(call_type, type_names, "Unknown (%d)"));
    info_builder_append(&info_builder, ") => ");


    // Empty map
    p_next++;
    // TODO: figure out what it is


    // Error
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("Error name should be STR");
        return 1;
    }
    const char *error_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_error, tvb, offset, 0, error_name);
    info_builder_append_abbrev_max(&info_builder, error_name, 48);

    return 0;
}

static int decode_msg(tvbuff_t *tvb _U_, int offset, int len, packet_info *pinfo _U_,
                      proto_tree *tree _U_, void *data _U_, proto_tree *jbl _U_, msgpack_object *object, char *str) {
    if (object->type != MSGPACK_OBJECT_ARRAY) {
        fprintf(stderr, "WRONG TYPE: %d (expected array, %d)\n", object->type, MSGPACK_OBJECT_ARRAY);
        return 1;
    }

    int array_len = object->via.array.size;
    if (array_len < 3) {
        fprintf(stderr, "Wrong array length: expected at least 3, got: %d\n", array_len);
        return 1;
    }

    msgpack_object* p = object->via.array.ptr;
    msgpack_object* const p_end = object->via.array.ptr + array_len;

    if (p->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        fprintf(stderr, "WRONG type: %d (expected positive int, %d)\n", p->type, MSGPACK_OBJECT_POSITIVE_INTEGER);
        return 1;
    }

    guint type = (guint) p->via.i64;
    proto_tree_add_uint(jbl, hf_jbl_type, tvb, offset, 0, type);

    info_builder_append(&info_builder, " ");
    info_builder_append(&info_builder, val_to_str(type, type_names, "Unknown"));
    info_builder_append(&info_builder, "  ");

    int ret = 0;
    p++;
    switch (type) {
        case JBL_MSG_ERROR:
            decode_msg_error(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_PUBLISH:
            decode_msg_publish(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_SUBSCRIBE:
            decode_msg_subscribe(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_SUBSCRIBED:
            decode_msg_subscribed(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_EVENT:
            decode_msg_event(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_CALL:
            decode_msg_call(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_CALL_RESULT:
            decode_msg_call_result(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_REGISTER_RPC:
            decode_msg_register(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_REGISTERED_RPC:
            decode_msg_registered(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_INVOKE_RPC:
            decode_msg_invoke(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case JBL_MSG_INVOKE_YIELD:
            decode_msg_yield(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        default:
            ret = 1;
            break;
    }

    const char *dot = "...";
    char save[4];
    bool yes = FALSE;
    if (strlen(str) > 48) {
        memcpy(save, str + 45, 4);
        memcpy(str + 45, dot, 4);
        yes = TRUE;
    }
    proto_item *x = proto_tree_add_string(jbl, hf_jbl_msg_data_short, tvb, offset, len, str);
    if (yes) {
        memcpy(str + 45, save, 4);
    }
    proto_tree * sub = proto_item_add_subtree(x, ett_jbl);
    proto_tree_add_string(sub, hf_jbl_msg_data_full, tvb, offset, len, str);

    proto_item_append_text(jbl, ", Type: %s (%d)", val_to_str(type, type_names, "Unknown (0x%02x)"), type);

    return ret;
}

static void append_port_info_to_builder(struct _info_builder *builder, packet_info *pinfo) {
    if (pinfo->srcport == JBL_PORT) {
        info_builder_append(builder, "→ ");
        info_builder_append_num(builder, pinfo->destport);
    } else if (pinfo->destport == JBL_PORT) {
        info_builder_append_num(builder, pinfo->srcport);
        info_builder_append(builder, " →");
    } else {
        info_builder_append_num(builder, pinfo->srcport);
        info_builder_append(builder, " → ");
        info_builder_append_num(builder, pinfo->destport);
    }
    info_builder_append(builder, " ");
}

static int decode_msgpack(tvbuff_t *tvb _U_, int offset, int len, packet_info *pinfo,
                          proto_tree *tree _U_, void *data _U_, proto_tree *jbl _U_, void *bytes, int size) {
    msgpack_zone mempool;
    msgpack_object deserialized;
    char str[STR_SIZE];

    msgpack_zone_init(&mempool, MSGPACK_MEMPOOL_SIZE);
    msgpack_unpack(bytes, size, NULL, &mempool, &deserialized);
    
    msgpack_object_print_buffer(str, STR_SIZE, deserialized);
    str[STR_SIZE - 1] = '\0';
    
    int ret = decode_msg(tvb, offset, len, pinfo, tree, data, jbl, &deserialized, str);
    
    if (ret) {
        info_builder_append_max(&info_builder, str, MAX_INFO_SIZE);
    }
    col_add_str(pinfo->cinfo, COL_INFO, info_builder.buf);

    msgpack_zone_destroy(&mempool);

    return 0;
}

static guint32 get_jbl_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    guint32 len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

    if (len == JBL_HANDSHAKE_MAGIC) {
        return JBL_MINIMUM_PDU_LENGTH;
    }
    return len + JBL_MINIMUM_PDU_LENGTH;
}

#define BUFF_SIZE 2048

static int dissect_jbl_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    gint offset = 0;

    bool is_multi = FALSE;

    // Note: for now, data is a pointer to a "first" bool: TRUE for first PDU
    // in segment, FALSE for following PDUs.
    if (*(bool *) data) {
        *(bool *) data = FALSE;
    } else {
        is_multi = TRUE;
    }
    
    reset_state();

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "JBL");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    
    guint data_len = tvb_captured_length(tvb);

    if (data_len < JBL_MINIMUM_PDU_LENGTH) {
        fprintf(stderr, "Data len too short: %u\n", data_len);
        return -1;
    }

    // Add a payload label in the tree
    proto_item *ti = proto_tree_add_item(tree, proto_jbl, tvb, 0, -1,ENC_NA);
    proto_tree *jbl_tree = proto_item_add_subtree(ti, ett_jbl);

    append_port_info_to_builder(&info_builder, pinfo);

    if (is_multi) {
        info_builder_append(&info_builder, " ** MULTI PDUs ** ");
        // TODO: ideally we'd add this one a bit further down in the tree
        proto_item * multi_item = proto_tree_add_boolean(jbl_tree, hf_jbl_multi_pdu, tvb, offset, 0, TRUE);
        proto_item_set_generated(multi_item);
    }

    guint work_len = 0;
    
    guint32 len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

    // Short circuit the special non-msgpack handshake
    if (data_len == 4 && len == JBL_HANDSHAKE_MAGIC) {
        proto_tree_add_item(jbl_tree, hf_jbl_handshake, tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ", Len: %u, Handshake", data_len);
        info_builder_append(&info_builder, " JBL HANDSHAKE");
        col_add_str(pinfo->cinfo, COL_INFO, info_builder.buf);
        return data_len;
    }

    guint32 expected_len = data_len - 4;

    if (len > expected_len) {
        fprintf(stderr, "ah, a case where len is wrong: %x (%d)  vs  %d\n", len, len, data_len);
        work_len = data_len;
        offset = 0;
    } else {
        if (len < expected_len) {
            fprintf(stderr, "jbl: underflow, len=%u (%x), actual=%d\n", len, len, expected_len);
            proto_item_append_text(ti, " (underflow, expected: %u)", expected_len);
            // keep going, and fail
        }
        work_len = expected_len;
        offset = 4;
    }

    proto_item_append_text(ti, ", Len: %u", work_len);
    if (len != work_len) {
        proto_item_append_text(ti, " (inferred)");
        proto_tree_add_uint(jbl_tree, hf_jbl_len, tvb, 0, 0, work_len);
    } else {
        proto_tree_add_item(jbl_tree, hf_jbl_len, tvb, 0, 4, ENC_BIG_ENDIAN);
    }

    void *bytes = tvb_memdup(wmem_packet_scope(), tvb, offset, work_len);

    decode_msgpack(tvb, offset, work_len, pinfo, tree, data, ti, bytes, work_len);

    return tvb_captured_length(tvb);
}

static int dissect_jbl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    bool first = TRUE;
    tcp_dissect_pdus(tvb, pinfo, tree, jbl_desegment, JBL_MINIMUM_PDU_LENGTH,
                     get_jbl_pdu_len, dissect_jbl_pdu, &first);
    return tvb_captured_length(tvb);
}

void proto_register_jbl(void) {
    fprintf(stderr, "REGISTERING JBL!!!! ************************ \n");
    
    init_param_table();
    
    static hf_register_info hf[] = {
        { &hf_jbl_handshake,
            { "Handshake", "jbl.handshake", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_type,
            { "Type", "jbl.type", FT_UINT8, BASE_DEC,
                VALS (type_names), 0x0, NULL, HFILL }},
        { &hf_jbl_call_type,
            { "Call Type", "jbl.call_type", FT_UINT8, BASE_DEC,
                VALS (type_names), 0x0, NULL, HFILL }},
        { &hf_jbl_len,
            { "Length", "jbl.len", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_multi_pdu,
            { "Multi PDU", "jbl.multi_pdu", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_msg_data_short,
            { "Raw message", "jbl.raw_msg_short", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_msg_data_full,
            { "Data", "jbl.raw_msg", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_seq_num,
            { "Sequence", "jbl.seq_num", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_event_name,
            { "Event Name", "jbl.event_name", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_error,
            { "Error", "jbl.error", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwargs,
            { "Keyworded-Args", "jbl.kwargs", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_key,
            { "Key", "jbl.kwarg_key", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_val,
            { "Value", "jbl.kwarg_val", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_thread_id,
            { "Thread Id", "jbl.kwarg_thread_id", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_service,
            { "Service", "jbl.kwarg_service", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_state,
            { "State", "jbl.kwarg_state", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_dis_mode,
            { "Dis_mode", "jbl.kwarg_dis_mode", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_dis_time,
            { "Dis_time", "jbl.kwarg_dis_time", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_dis_mand,
            { "Dis_mand", "jbl.kwarg_dis_mand", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_action,
            { "Action", "jbl.kwarg_action", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_level,
            { "Level", "jbl.kwarg_level", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_timeout,
            { "Timeout", "jbl.kwarg_timeout", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_player,
            { "Player", "jbl.kwarg_player", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwarg_nextsrc,
            { "Nextsrc", "jbl.kwarg_nextsrc", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_args,
            { "Args", "jbl.args", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_int,
            { "Int", "jbl.arg_int", FT_INT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_bool,
            { "Bool", "jbl.arg_bool", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_str,
            { "String", "jbl.arg_str", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_other,
            { "Other", "jbl.arg_other", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_sub_id,
            { "Sub Id", "jbl.sub_id", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_event_id,
            { "Event Id", "jbl.event_id", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_rpc_name,
            { "RPC Name", "jbl.rpc_name", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_rpc_id,
            { "RPC Id", "jbl.rpc_id", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }}

        
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_jbl
    };

    proto_jbl = proto_register_protocol (
        "JBL Protocol", /* name        */
        "JBL",          /* short_name  */
        "jbl"           /* filter_name */
        );

    proto_register_field_array(proto_jbl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module_t * jbl_module = prefs_register_protocol(proto_jbl, NULL);

    prefs_register_bool_preference(jbl_module, "desegment",
                                   "Reassemble JBL messages spanning multiple TCP segments",
                                   "Whether the JBL dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &jbl_desegment);
    prefs_register_bool_preference(jbl_module, "abbreviate",
                                   "Shorten \"com.harman.\" prefix to \"c.h.\" in info line",
                                   "Whether the JBL dissector should abbreviate "
                                   "\"com.harman.\" prefixes in the info line, for example: "
                                   "\"com.harman.HDMI\" -> \"c.h.HDMI\"",
                                   &jbl_abbreviate);
    prefs_register_bool_preference(jbl_module, "resolve_calls",
                                   "Resolve names in RPC calls (CallResult/Yield)",
                                   "Keep track of RPC names used in each Call and Invoke "
                                   "message to be able to resolve RPC names in CallResult "
                                   "and Yield messages. Uses more memory, but not too much.",
                                   &jbl_resolve_calls);
}


void proto_reg_handoff_jbl(void) {
    static dissector_handle_t jbl_handle;

    jbl_handle = create_dissector_handle(dissect_jbl, proto_jbl);
    dissector_add_uint_with_preference("tcp.port", JBL_PORT, jbl_handle);
}
