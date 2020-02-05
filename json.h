#ifndef __JSON__H
#define __JSON__H

#include "lib/output_buffer.h"

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

int json_object_add_value_type(struct json_object *obj, const char *name,
			       const struct json_value *val);

static inline int json_object_add_value_int(struct json_object *obj,
					    const char *name, long long val)
{
	struct json_value arg = {
		.type = JSON_TYPE_INTEGER,
		.integer_number = val,
	};

	return json_object_add_value_type(obj, name, &arg);
}

static inline int json_object_add_value_float(struct json_object *obj,
					      const char *name, double val)
{
	struct json_value arg = {
		.type = JSON_TYPE_FLOAT,
		.float_number = val,
	};

	return json_object_add_value_type(obj, name, &arg);
}

static inline int json_object_add_value_string(struct json_object *obj,
					       const char *name,
					       const char *val)
{
	struct json_value arg = {
		.type = JSON_TYPE_STRING,
		.string = (char *)val,
	};

	return json_object_add_value_type(obj, name, &arg);
}

static inline int json_object_add_value_object(struct json_object *obj,
					       const char *name,
					       struct json_object *val)
{
	struct json_value arg = {
		.type = JSON_TYPE_OBJECT,
		.object = val,
	};

	return json_object_add_value_type(obj, name, &arg);
}

static inline int json_object_add_value_array(struct json_object *obj,
					      const char *name,
					      struct json_array *val)
{
	struct json_value arg = {
		.type = JSON_TYPE_ARRAY,
		.array = val,
	};

	return json_object_add_value_type(obj, name, &arg);
}

int json_array_add_value_type(struct json_array *array,
			      const struct json_value *val);

static inline int json_array_add_value_int(struct json_array *obj,
					   long long val)
{
	struct json_value arg = {
		.type = JSON_TYPE_INTEGER,
		.integer_number = val,
	};

	return json_array_add_value_type(obj, &arg);
}

static inline int json_array_add_value_float(struct json_array *obj,
					     double val)
{
	struct json_value arg = {
		.type = JSON_TYPE_FLOAT,
		.float_number = val,
	};

	return json_array_add_value_type(obj, &arg);
}

static inline int json_array_add_value_string(struct json_array *obj,
					      const char *val)
{
	struct json_value arg = {
		.type = JSON_TYPE_STRING,
		.string = (char *)val,
	};

	return json_array_add_value_type(obj, &arg);
}

static inline int json_array_add_value_object(struct json_array *obj,
					      struct json_object *val)
{
	struct json_value arg = {
		.type = JSON_TYPE_OBJECT,
		.object = val,
	};

	return json_array_add_value_type(obj, &arg);
}

static inline int json_array_add_value_array(struct json_array *obj,
					     struct json_array *val)
{
	struct json_value arg = {
		.type = JSON_TYPE_ARRAY,
		.array = val,
	};

	return json_array_add_value_type(obj, &arg);
}

#define json_array_last_value_object(obj) \
	(obj->values[obj->value_cnt - 1]->object)

void json_print_object(struct json_object *obj, struct buf_output *out);
#endif
