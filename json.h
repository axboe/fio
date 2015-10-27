#ifndef __JSON__H
#define __JSON__H

#include "lib/output_buffer.h"

struct json_object;
struct json_array;
struct json_pair;

#define JSON_TYPE_STRING 0
#define JSON_TYPE_INTEGER 1
#define JSON_TYPE_FLOAT 2
#define JSON_TYPE_OBJECT 3
#define JSON_TYPE_ARRAY 4
#define JSON_PARENT_TYPE_PAIR 0
#define JSON_PARENT_TYPE_ARRAY 1
struct json_value {
	int type;
	union {
		long long integer_number;
		double float_number;
		char *string;
		struct json_object *object;
		struct json_array *array;
	};
	int parent_type;
	union {
		struct json_pair *parent_pair;
		struct json_array *parent_array;
	};
};

struct json_array {
	struct json_value **values;
	int value_cnt;
	struct json_value *parent;
};

struct json_object {
	struct json_pair **pairs;
	int pair_cnt;
	struct json_value *parent;
};

struct json_pair {
	char *name;
	struct json_value *value;
	struct json_object *parent;
};

struct json_object *json_create_object(void);
struct json_array *json_create_array(void);

void json_free_object(struct json_object *obj);

int json_object_add_value_type(struct json_object *obj, const char *name, int type, ...);
#define json_object_add_value_int(obj, name, val) \
	json_object_add_value_type((obj), name, JSON_TYPE_INTEGER, (long long) (val))
#define json_object_add_value_float(obj, name, val) \
	json_object_add_value_type((obj), name, JSON_TYPE_FLOAT, (val))
#define json_object_add_value_string(obj, name, val) \
	json_object_add_value_type((obj), name, JSON_TYPE_STRING, (val))
#define json_object_add_value_object(obj, name, val) \
	json_object_add_value_type((obj), name, JSON_TYPE_OBJECT, (val))
#define json_object_add_value_array(obj, name, val) \
	json_object_add_value_type((obj), name, JSON_TYPE_ARRAY, (val))
int json_array_add_value_type(struct json_array *array, int type, ...);
#define json_array_add_value_int(obj, val) \
	json_array_add_value_type((obj), JSON_TYPE_INTEGER, (val))
#define json_array_add_value_float(obj, val) \
	json_array_add_value_type((obj), JSON_TYPE_FLOAT, (val))
#define json_array_add_value_string(obj, val) \
	json_array_add_value_type((obj), JSON_TYPE_STRING, (val))
#define json_array_add_value_object(obj, val) \
	json_array_add_value_type((obj), JSON_TYPE_OBJECT, (val))
#define json_array_add_value_array(obj, val) \
	json_array_add_value_type((obj), JSON_TYPE_ARRAY, (val))

#define json_array_last_value_object(obj) \
	(obj->values[obj->value_cnt - 1]->object)

void json_print_object(struct json_object *obj, struct buf_output *out);
#endif
