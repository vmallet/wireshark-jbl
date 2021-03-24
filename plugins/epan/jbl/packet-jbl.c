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

#include "msgpack.h"

#define JBL_PORT 9999

static int proto_jbl = -1;

static int hf_jbl_pdu_type = -1;
static int hf_jbl_pdu_len = -1;
static int hf_jbl_msg_data_short = -1;
static int hf_jbl_msg_data_full = -1;
static int hf_jbl_seq_num = -1;
static int hf_jbl_msg_event_name = -1;
static int hf_jbl_sub_id = -1;
static int hf_jbl_sub_name = -1;
static int hf_jbl_event_id = -1;

static int hf_jbl_kwarg_thread_id = -1;
static int hf_jbl_kwarg_state = -1;
static int hf_jbl_kwarg_service = -1;

//static int hf_jbl_param_xxx = -1;

static int hf_jbl_args = -1;
static int hf_jbl_arg_1 = -1;
static int hf_jbl_arg_2 = -1;
static int hf_jbl_arg_3 = -1;
static int hf_jbl_arg_4 = -1;
static int hf_jbl_arg_5 = -1;

static int hf_jbl_res_int_1 = -1;
static int hf_jbl_res_bool_1 = -1;
static int hf_jbl_res_str_1 = -1;
static int hf_jbl_res_rest = -1;

static int hf_jbl_kwargs = -1;

static gint ett_jbl = -1;


static GHashTable *jbl_params = NULL;


static int *jbl_arg_list[] = {
    &hf_jbl_arg_1,
    &hf_jbl_arg_2,
    &hf_jbl_arg_3,
    &hf_jbl_arg_4,
    &hf_jbl_arg_5
};

static const int jbl_arg_list_length = sizeof(jbl_arg_list) / sizeof(jbl_arg_list[0]);

static int jbl_cur_arg = 0;



static const value_string req_names[] = {
    { 16, "Publish" },
    { 32, "Subscribe" },
    { 33, "Subscribed" },
    { 34, "Unsubscribe" },
    { 35, "Unsubscribed" },
    { 36, "Event" },
    { 48, "Call" },
    { 49, "Cancel" },
    { 50, "CallResult" },
    { 64, "Register" },
    { 65, "Registered" },
    { 66, "Unregister" },
    { 67, "Unregistered" },
    { 68, "Invoke" },
    { 69, "Interrupt" },
    { 70, "Yield" },
    { 0, "NULL" }
};

static struct _info_builder {
    char * buf;
    int size;
    char *cur;
} info_builder = {
    NULL, 0, NULL
};


typedef struct _jbl_conv_data {
    wmem_map_t *sub_reqs; // seq_num -> event_name
    wmem_map_t *subs; // sub_id -> event_name
} jbl_conv_data_t;


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

static void info_builder_append_num(struct _info_builder *builder, guint64 num) {
    char buf[JBL_BUILDER_NUM_TMP_BUF];
    snprintf(buf, JBL_BUILDER_NUM_TMP_BUF, "%llu", num);
    buf[JBL_BUILDER_NUM_TMP_BUF - 1] = '\0';
    //TODO: check_init(builder);
    info_builder_append(builder, buf);
}

#define JBL_STR_ABBREV_PREFIX   "com.harman."
#define JBL_STR_ABBREV_SUB      "c.h."
static const int jbl_abbrev_prefix_len = strlen(JBL_STR_ABBREV_PREFIX);
static const int jbl_abbrev_sub_len = strlen(JBL_STR_ABBREV_SUB);

/* Shortens "com.harman." leading string as "c.h." */
static void info_builder_append_abbrev_max(struct _info_builder *builder, const char *s, int maxlen) {
    int max = maxlen;
    const char *p = s;
    if (0 == strncmp(s, JBL_STR_ABBREV_PREFIX, jbl_abbrev_prefix_len)) {
        info_builder_append_max(builder, JBL_STR_ABBREV_SUB, max);
        max -= jbl_abbrev_sub_len;
        p += jbl_abbrev_prefix_len;
    }
    info_builder_append_max(builder, p, max);
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
}

#define INFO_BUILDER_SIZE 512

static void reset_state() {
    jbl_cur_arg = 0;
    info_builder_init(&info_builder, INFO_BUILDER_SIZE);
}

static int * next_hf_arg() {
    if (jbl_cur_arg < jbl_arg_list_length) {
        return jbl_arg_list[jbl_cur_arg++];
    }
    return NULL;
}


//static void
//set_col_info(packet_info *pinfo, char *buf, int truncate_size)
//{
//    char c = buf[truncate_size];
//    buf[truncate_size] = '\0';
//    col_add_str(pinfo->cinfo, COL_INFO, buf);
//    buf[truncate_size] = c;
//}

static void error(char *msg) { //TODO: do something useful
    fprintf(stderr, "%s\n", msg);
}

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
    
    return buf;
}

static gint64 * make_durable_key_int64(gint64 key_val) {
    gint64 * key = wmem_alloc(wmem_file_scope(), sizeof(gint64));
    *key = key_val;
    return key;
}

static void init_conv_data(jbl_conv_data_t *data) {
    data->sub_reqs = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    data->subs = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    wmem_map_insert(data->subs, make_durable_key_int64(42), "salut les amis");
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


static int decode_msg_publish(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                              proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    
    // [16, 13, {}, "com.harman.test.inputEvent", ["ir-volumeup", "1"]]
    // [16, 187003, {}, "com.harman.music.stateChanged", ["com.harman.HDMI"], {"service"=>"HDMI", "state"=>"paused"}]
    info_builder_append(&info_builder, "Publish: ");
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
    info_builder_append(&info_builder, "Seq=");
    info_builder_append_num(&info_builder, num);
                            

    // Empty map
    p_next++; // still safe
    // TODO: name it
    //TODO: do it;
    

    // event name
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("Event name should be string");
        return 1;
    }
    const char *event_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_msg_event_name, tvb, offset, 0, event_name);
    info_builder_append(&info_builder, ", \"");
    info_builder_append_abbrev_max(&info_builder, event_name, 48);
    info_builder_append(&info_builder, "\"");
    

    
    // event args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    msgpack_object *args = p_next;
    if (args->type != MSGPACK_OBJECT_ARRAY) {
        error("Event args should be ARRAY");
        return 1;
    }
    
    guint args_size = (guint) args->via.u64;
    proto_item *item3 = proto_tree_add_uint(jbl, hf_jbl_args, tvb, offset, 0, args_size);
    msgpack_object * ap = args->via.array.ptr;
    msgpack_object * const apend = args->via.array.ptr + args_size;
    if (args_size == 0)
    {
        proto_item_append_text(item3, " (empty)");
    }
    else
    {
        proto_tree * targs = proto_item_add_subtree(item3, ett_jbl);
        for (; ap < apend; ++ap)
        {
            const char *str = get_object_str(ap);
            int * hf_arg = next_hf_arg();
            if (hf_arg == NULL) {
                fprintf(stderr, "Ran out of args for: %s\n", str);
            } else {
                proto_tree_add_string(targs, *hf_arg, tvb, offset, 0, str);
            }
            info_builder_append(&info_builder, ", \"");
            info_builder_append_max(&info_builder, str, 48);
            info_builder_append(&info_builder, "\"");
        }
    }

    
    // Event kwargs
    p_next++;
    if (p_next >= p_end) {
        info_builder_append(&info_builder, ")");
        return 0;
    }
    msgpack_object *kwargs = p_next;
    if (kwargs->type != MSGPACK_OBJECT_MAP) {
        error("Event kwargs should be MAP");
        info_builder_append(&info_builder, ")");
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
                fprintf(stderr, "No mapping for this guy: %s -> %s\n", key, get_object_str(&kvp->val));
            }
        }
    }
    
    
    info_builder_append(&info_builder, ")");
    return 0;
}

//TODO: brutal clone of decode_msg_publish for now; try to reuse a bit more once it becomes apparent
static int decode_msg_event(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                            proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [36, 10, 4588522949814990, {}, ["ir-power", "0"]]
    info_builder_append(&info_builder, "Event: ");
    if ((p_end - p_next) < 4) {
        //TODO: include err in info?
        info_builder_append(&info_builder, "Not enough arguments, needed at least 5, got: ");
        info_builder_append_num(&info_builder, (int) (p_end - p_next));;
        error("Protocol error: publish needs 5 args at least");
        return 1;
    }
    
    // sub_id
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: publish arg 2 should be an int");
        return 1;
    }
    
    gint64 sub_id =  p_next->via.i64; //TODO: is it really an int64?
    proto_tree_add_uint(jbl, hf_jbl_sub_id, tvb, offset, 0, (guint) sub_id); //TODO CAST
    info_builder_append(&info_builder, "SubId=");
    info_builder_append_num(&info_builder, sub_id);

    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    char * sub_name = wmem_map_lookup(data->subs, &sub_id);
    if (!sub_name) {
        fprintf(stderr, "NOT FOUND SUB: %lld\n", sub_id);
    } else {
        proto_tree_add_string(jbl, hf_jbl_sub_name, tvb, offset, 0, sub_name);
        fprintf(stderr, "YESSSSSSSS: %lld: %s\n", sub_id, sub_name);
        info_builder_append(&info_builder, " (");
        info_builder_append_abbrev_max(&info_builder, sub_name, 48);
        info_builder_append(&info_builder, ")");
    }
    
    // event_id
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: publish arg 3 should be an int");
        return 1;
    }
    
    guint64 event_id = p_next->via.i64; //TODO: is it really an int64?
    proto_tree_add_uint64(jbl, hf_jbl_event_id, tvb, offset, 0, event_id);
    info_builder_append(&info_builder, " EventId=");
    info_builder_append_num(&info_builder, event_id);


    // Empty map
    p_next++; // still safe
    // TODO: name it
    //TODO: do it;
    

    // event name
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("Event name should be string");
        return 1;
    }
    const char *event_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_msg_event_name, tvb, offset, 0, event_name);
    info_builder_append(&info_builder, ", \"");
    info_builder_append_abbrev_max(&info_builder, event_name, 48);
    info_builder_append(&info_builder, "\"");
    

    
    // event args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    msgpack_object *args = p_next;
    if (args->type != MSGPACK_OBJECT_ARRAY) {
        error("Event args should be ARRAY");
        return 1;
    }
    
    guint args_size = (guint) args->via.u64;
    proto_item *item3 = proto_tree_add_uint(jbl, hf_jbl_args, tvb, offset, 0, args_size);
    msgpack_object * ap = args->via.array.ptr;
    msgpack_object * const apend = args->via.array.ptr + args_size;
    if (args_size == 0) {
        proto_item_append_text(item3, " (empty)");
    } else {
        proto_tree * targs = proto_item_add_subtree(item3, ett_jbl);
        for (; ap < apend; ++ap) {
            const char *str = get_object_str(ap);
            int * hf_arg = next_hf_arg();
            if (hf_arg == NULL) {
                fprintf(stderr, "Ran out of args for: %s\n", str);
            } else {
                proto_tree_add_string(targs, *hf_arg, tvb, offset, 0, str);
            }
            info_builder_append(&info_builder, ", \"");
            info_builder_append_max(&info_builder, str, 48);
            info_builder_append(&info_builder, "\"");
        }
    }

    
    // Event kwargs
    p_next++;
    if (p_next >= p_end) {
        info_builder_append(&info_builder, ")");
        return 0;
    }
    msgpack_object *kwargs = p_next;
    if (kwargs->type != MSGPACK_OBJECT_MAP) {
        error("Event kwargs should be MAP");
        info_builder_append(&info_builder, ")");
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
                fprintf(stderr, "No mapping for this guy: %s -> %s\n", key, get_object_str(&kvp->val));
            }
        }
    }
    
    
    info_builder_append(&info_builder, ")");
    return 0;
}

static int decode_msg_subscribe(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                                proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [32, 9, {}, "com.harman.powerModeChanged"]
    info_builder_append(&info_builder, "Event: ");
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
        error("Procotol error: event arg 2 should be an int");
        return 1;
    }
    
    guint64 seq_num = p_next->via.u64;
    proto_tree_add_uint64(jbl, hf_jbl_seq_num, tvb, offset, 0, seq_num);
    info_builder_append(&info_builder, "Seq=");
    info_builder_append_num(&info_builder, seq_num);

    // Empty map
    p_next++; // still safe
    // TODO: name it
    //TODO: do it;
    
    // event name
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_STR) {
        error("Event name should be string");
        return 1;
    }
    const char *event_name = get_object_str(p_next);
    proto_tree_add_string(jbl, hf_jbl_msg_event_name, tvb, offset, 0, event_name);
    info_builder_append(&info_builder, ", \"");
    info_builder_append_abbrev_max(&info_builder, event_name, 48);
    info_builder_append(&info_builder, "\"");
    
    const char *durable_name = wmem_strdup(wmem_file_scope(), event_name);
    gint64 *key = make_durable_key_int64(seq_num);
    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    wmem_map_insert(data->sub_reqs, key, (void *) durable_name);
    
    info_builder_append(&info_builder, ")");
    return 0;
}

static int decode_msg_subscribed(tvbuff_t *tvb, int offset, int len _U_, packet_info *pinfo _U_,
                                 proto_tree *jbl, msgpack_object *p_next, msgpack_object *p_end) {
    // [33, 9, 118]
    info_builder_append(&info_builder, "Subscribed: ");
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
    info_builder_append(&info_builder, "Seq=");
    info_builder_append_num(&info_builder, seq_num);

    // sub_id
    p_next++;
    if (p_next->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        //TODO: include err in info?
        error("Procotol error: publish arg 2 should be an int");
        return 1;
    }
    
    gint64 sub_id = p_next->via.i64; //TODO: is it really an int64?
//    proto_tree_add_uint(jbl, hf_jbl_sub_id, tvb, offset, 0, sub_id);
    info_builder_append(&info_builder, " SubId=");
    info_builder_append_num(&info_builder, sub_id);

    jbl_conv_data_t *data = get_or_create_conv_data(pinfo);
    char * event_name = wmem_map_lookup(data->sub_reqs, &seq_num);
    if (event_name) {
        fprintf(stderr, "found mapping! %s\n", event_name);
        gint64 *key = make_durable_key_int64(sub_id);
        wmem_map_insert(data->subs, key, event_name);
    } else {
        fprintf(stderr, "subscribe miss: seq_num = %lld\n", seq_num);
    }
    
    info_builder_append(&info_builder, ")");
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

    info_builder_append(&info_builder, "Call Result: ");
    if ((p_end - p_next) < 2) {
        //TODO: include err in info?
        error("Protocol error: call result needs 2 args at least");
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
    info_builder_append(&info_builder, "Seq=");
    info_builder_append_num(&info_builder, num);
                            

    // Empty map
    p_next++; // still safe
    // TODO: name it
    //TODO: do it;
    

//    // event name
//    p_next++;
//    if (p_next->type != MSGPACK_OBJECT_STR) {
//        error("Event name should be string");
//        return 1;
//    }
//    const char *event_name = get_object_str(p_next);
//    proto_tree_add_string(jbl, hf_jbl_msg_event_name, tvb, offset, 0, event_name);
//    info_builder_append(&info_builder, ", \"");
//    info_builder_append_abbrev_max(&info_builder, event_name, 48);
//    info_builder_append(&info_builder, "\"");
    

    
    // event args
    p_next++;
    if (p_next >= p_end) {
        return 0;
    }
    msgpack_object *res = p_next;
    if (res->type != MSGPACK_OBJECT_ARRAY) {
        error("Call results should be ARRAY");
        return 1;
    }
    
    guint res_size = (guint) res->via.u64;
    //TODO: it's not hf_jbl_args, it's res
    proto_item *item3 = proto_tree_add_uint(jbl, hf_jbl_args, tvb, offset, 0, res_size); //TODO
    msgpack_object * ap = res->via.array.ptr;
    msgpack_object * const apend = res->via.array.ptr + res_size;
    if (res_size == 0) {
        proto_item_append_text(item3, " (empty)");
    } else {
        proto_tree * tres = proto_item_add_subtree(item3, ett_jbl);
        //TODO: do better with the hack below
        bool rint = false;
//        bool rbool = false;
//        bool rstr = false;
        bool use_rest = false;
        char rbuf[1024]; // TODO: really?
        rbuf[0] = '\0';
        char *pbuf = rbuf;
        for (; ap < apend; ++ap) {
            if (!use_rest) {
                switch (ap->type) {
                    case MSGPACK_OBJECT_POSITIVE_INTEGER:
                        if (rint) {
                            use_rest = true;
                        } else {
                            gint64 v64 = ap->via.i64;
                            proto_tree_add_int64(tres, hf_jbl_res_int_1, tvb, offset, 0, v64);
                            rint = true;
                        }
                        break;
                    default:
                        use_rest = true;
                        break;
                }
            }
            
            if (use_rest) {
                if (*rbuf) {
                    strcat(rbuf, ", "); //TODO: len safety
                }
                msgpack_object_print_buffer(pbuf, sizeof(rbuf) - (pbuf - rbuf), *ap);
                pbuf = rbuf + strlen(rbuf);
            }
//            const char *str = get_object_str(ap);
//            int * hf_arg = next_hf_arg();
//            if (hf_arg == NULL) {
//                fprintf(stderr, "Ran out of args for: %s\n", str);
//            } else {
//                proto_tree_add_string(targs, *hf_arg, tvb, offset, 0, str);
//            }
        }
        
        if (*rbuf) {
            proto_tree_add_string(tres, hf_jbl_res_rest, tvb, offset, 0, rbuf);
        }
    }

    
//    // Event kwargs
//    p_next++;
//    if (p_next >= p_end) {
//        info_builder_append(&info_builder, ")");
//        return 0;
//    }
//    msgpack_object *kwargs = p_next;
//    if (kwargs->type != MSGPACK_OBJECT_MAP) {
//        error("Event kwargs should be MAP");
//        info_builder_append(&info_builder, ")");
//        return 1;
//    }
//
//    guint kwargs_size = (guint) kwargs->via.u64;
//    proto_item *item2 = proto_tree_add_uint(jbl, hf_jbl_kwargs, tvb, offset, 0, kwargs_size);
//    msgpack_object_kv* kvp = kwargs->via.map.ptr;
//    msgpack_object_kv* const kvpend = kwargs->via.map.ptr + kwargs_size;
//    if (kwargs_size == 0)
//    {
//        proto_item_append_text(item2, " (empty)");
//    } else
//    {
//        proto_tree * sub = proto_item_add_subtree(item2, ett_jbl);
//        for (; kvp < kvpend; ++kvp)
//        {
//            const char * key = get_object_str(&kvp->key);
//            int *hf_param = g_hash_table_lookup(jbl_params, key);
//            if (hf_param) {
//                //TODO: decide type based on hf_param, not wire type. For now need something that runs
//                switch (kvp->val.type) {
//                    case MSGPACK_OBJECT_POSITIVE_INTEGER:
//                        proto_tree_add_uint64(sub, *hf_param, tvb, offset, 0, kvp->val.via.u64);
//                        break;
//                    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
//                        proto_tree_add_int64(sub, *hf_param, tvb, offset, 0, kvp->val.via.i64);
//                        break;
//                    default:
//                        proto_tree_add_string(sub, *hf_param, tvb, offset, 0, get_object_str(&kvp->val));
//                        break;
//                }
//            } else {
//                fprintf(stderr, "No mapping for this guy: %s -> %s\n", key, get_object_str(&kvp->val));
//            }
//        }
//    }
    
    
    info_builder_append(&info_builder, ")");
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
        fprintf(stderr, "WRONG req type: %d (expected positive int, %d)\n", p->type, MSGPACK_OBJECT_POSITIVE_INTEGER);
        return 1;
    }
    
    guint type = (guint) p->via.i64; //TODO: is it really an int64?
    proto_tree_add_uint(jbl, hf_jbl_pdu_type, tvb, offset, 0, type);

    
    if (len == 70 && type == 16) {
        printf("check\n");
    }

    
    p++;
    switch (type) {
        case 16: //TODO const
            decode_msg_publish(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case 32: //TODO const
            decode_msg_subscribe(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case 33: //TODO const
            decode_msg_subscribed(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case 36: //TODO const
            decode_msg_event(tvb, offset, len, pinfo, jbl, p, p_end);
            break;
        case 50: //TODO const
            decode_msg_call_result(tvb, offset, len, pinfo, jbl, p, p_end);
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

        
    
    proto_item_append_text(jbl, ", Req: %s (%d)", val_to_str(type, req_names, "Unknown (0x%02x)"), type);
    
    return 0;
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
    
    /* deserialize the buffer into msgpack_object instance. */
    /* deserialized object is valid during the msgpack_zone instance alive. */
    msgpack_zone_init(&mempool, MSGPACK_MEMPOOL_SIZE);
    msgpack_unpack(bytes, size, NULL, &mempool, &deserialized);
    
    msgpack_object_print(stdout, deserialized);
    puts("");

    msgpack_object_print_buffer(str, STR_SIZE, deserialized);
    str[STR_SIZE - 1] = '\0';
    
    append_port_info_to_builder(&info_builder, pinfo);
    char *builder_cur = info_builder.cur;
    
    decode_msg(tvb, offset, len, pinfo, tree, data, jbl, &deserialized, str);
    
    if (info_builder.cur == builder_cur) {
        info_builder_append_max(&info_builder, str, MAX_INFO_SIZE);
    }
    col_add_str(pinfo->cinfo, COL_INFO, info_builder.buf);

    msgpack_zone_destroy(&mempool);

    return 0;
}

#define BUFF_SIZE 2048

static int dissect_jbl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    
    reset_state();
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "JBL");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    
    guint data_len = tvb_captured_length(tvb);
    
    
    
    
//    printf("\n");
//    printf("captured: %d   reported: %d\n",  tvb_captured_length(tvb), tvb_reported_length(tvb));
 
    if (data_len < 4) {
        fprintf(stderr, "Data len too short: %u\n", data_len);
        return -1;
    }

    // Add a payload label in the tree
    proto_item *ti = proto_tree_add_item(tree, proto_jbl, tvb, 0, -1,ENC_NA);
    proto_tree *jbl_tree = proto_item_add_subtree(ti, ett_jbl);

    guint work_len = 0;
    
    guint32 len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
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
        proto_tree_add_uint(jbl_tree, hf_jbl_pdu_len, tvb, 0, 0, work_len);
    } else {
        proto_tree_add_item(jbl_tree, hf_jbl_pdu_len, tvb, 0, 4, ENC_BIG_ENDIAN);
    }
    
    
    void *bytes = tvb_memdup(wmem_packet_scope(), tvb, offset, work_len);
//    pro(bytes, work_len, str, STR_SIZE);

    decode_msgpack(tvb, offset, work_len, pinfo, tree, data, ti, bytes, work_len);
    
//    proto_tree_add_item(jbl_tree, hf_jbl_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
//    offset += 1;

    

    
    
    return tvb_captured_length(tvb);
}

void proto_register_jbl(void) {
    fprintf(stderr, "REGISTERING JBL!!!! ************************ \n");
    
    init_param_table();
    
    static hf_register_info hf[] = {
        { &hf_jbl_pdu_type,
            { "Type", "jbl.type", FT_UINT8, BASE_DEC,
                VALS (req_names), 0x0, NULL, HFILL }},
        { &hf_jbl_pdu_len,
            { "Length", "jbl.len", FT_UINT32, BASE_DEC,
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
        { &hf_jbl_msg_event_name,
            { "Event Name", "jbl.event_name", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_kwargs,
            { "Keyworded-Args", "jbl.kwargs", FT_UINT32, BASE_DEC,
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
        { &hf_jbl_args,
            { "Args", "jbl.args", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_1,
            { "Args #1", "jbl.arg_1", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_2,
            { "Args #1", "jbl.arg_2", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_3,
            { "Args #2", "jbl.arg_3", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_4,
            { "Args #3", "jbl.arg_4", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_arg_5,
            { "Args #4", "jbl.arg_5", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_res_int_1,
            { "Int result #1", "jbl.res_int_1", FT_INT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_res_bool_1,
            { "Bool result #1", "jbl.res_bool_1", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_res_str_1,
            { "String result #1", "jbl.res_str_1", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_res_rest,
            { "Rest of results", "jbl.res_rest", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_sub_id,
            { "Sub Id", "jbl.sub_id", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_sub_name,
            { "Sub Name", "jbl.sub_name", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_jbl_event_id,
            { "Event Id", "jbl.event_id", FT_UINT64, BASE_DEC,
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
}


void proto_reg_handoff_jbl(void) {
    static dissector_handle_t jbl_handle;

    jbl_handle = create_dissector_handle(dissect_jbl, proto_jbl);
    dissector_add_uint("tcp.port", JBL_PORT, jbl_handle);
}