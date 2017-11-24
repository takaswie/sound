/*
 * compat ioctls for control API
 *
 *   Copyright (c) by Takashi Iwai <tiwai@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

/* this file included from control.c */

#include <linux/compat.h>
#include <linux/slab.h>

/*
 * In this file, System V ABIs for any 64 bit architecture are assumed:
 *  - Machine type for storage class of 1 byte has:
 *    - size: 1 byte
 *    - alignment: 1 byte
 *  - Machine type for storage class of 2 bytes has:
 *    - size: 2 bytes
 *    - alignment: 2 bytes
 *  - Machine type for storage class of 4 bytes has:
 *    - size: 4 bytes
 *    - alignment: 4 bytes
 *  - Machine type for storage class of 8 bytes has:
 *    - size: 8 bytes
 *    - alignment: 8 bytes
 *
 * And System V ABIs for modern 32 bit architecture are assumed to have the same
 * rule about size and alignment as the above machine types.
 *
 * As an exception, System V ABI for i386 architecture is assumed:
 *  - Machine type for storage class of 8 bytes has:
 *    - size: 8 bytes
 *    - alignment: 4 bytes
 *
 * Any System V ABIs are assumed to have the same rule for aggregates, unions
 * and alignment of members with bitfields. Additionally, 'packed' of attribute
 * is a hint for compiles to remove internal and tail paddings even if bitfields
 * are used.
 */

/*
 * In any System V ABI for 32 bit architecture, the maximum length of members on
 * this structure is 4 bytes. This member has 4 byte alignment and the size of
 * this structure is multiples of 4 bytes, equals to 72 bytes. However, total
 * size of all members is 70 bytes. As a result, 2 bytes are added as padding in
 * the end.
 */
struct snd_ctl_elem_list_32 {
	u32 offset;
	u32 space;
	u32 used;
	u32 count;
	u32 pids;		/* pointer on ILP32. */
	u8 reserved[50];
	u8 padding[2];
} __packed;

static int deserialize_from_elem_list_32(struct snd_ctl_file *ctl_file,
					 void *dst, void *src)
{
	struct snd_ctl_elem_list *data = dst;
	struct snd_ctl_elem_list_32 *data32 = src;

	data->offset = data32->offset;
	data->space = data32->space;
	data->used = data32->used;
	data->count = data32->count;

	data->pids = (struct snd_ctl_elem_id __user *)compat_ptr(data32->pids);

	memcpy(data->reserved, data32->reserved, sizeof(data->reserved));

	return 0;
}

static int serialize_to_elem_list_32(struct snd_ctl_file *ctl_file, void *dst,
				     void *src)
{
	struct snd_ctl_elem_list_32 *data32 = dst;
	struct snd_ctl_elem_list *data = src;

	data32->offset = data->offset;
	data32->space = data->space;
	data32->used = data->used;
	data32->count = data->count;

	data32->pids = (u32)ptr_to_compat(data->pids);

	memcpy(data32->reserved, data->reserved, sizeof(data32->reserved));

	return 0;
}

/*
 * In this structure, '.value' member includes double-word (= 64 bits) member
 * ('.integer64'). System V ABI for i386 architecture adopts different byte
 * alignment for this type (4 bytes) than the ones in the other architectures
 * (8 bytes). Fortunately, the total size of '.id', '.type', '.access', '.count'
 * and '.owner' is multiples of 8, and there's no issue for offset of the
 * '.value' member.
 */
struct snd_ctl_elem_info_32 {
	struct snd_ctl_elem_id id;
	s32 type;
	u32 access;
	u32 count;
	s32 owner;
	union {
		struct {
			s32 min;	/* long on ILP32. */
			s32 max;	/* long on ILP32. */
			s32 step;	/* long on ILP32. */
		} integer;
		struct {
			u64 min;
			u64 max;
			u64 step;
		} integer64;
		struct {
			u32 items;
			u32 item;
			s8 name[64];
			u64 names_ptr;
			u32 names_length;
		} enumerated;
		u8 reserved[128];
	} value;
	u16 dimen[4];
	u8 reserved[64 - 4 * sizeof(u16)];
} __packed;

static int deserialize_from_elem_info_32(struct snd_ctl_file *ctl_file,
					 void *dst, void *src)
{
	struct snd_ctl_elem_info *data = dst;
	struct snd_ctl_elem_info_32 *data32 = src;

	data->id = data32->id;
	data->type = data32->type;
	data->access = data32->access;
	data->count = data32->count;
	data->owner = data32->owner;

	if (data->type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		data->value.integer.min = (s64)data32->value.integer.min;
		data->value.integer.max = (s64)data32->value.integer.max;
		data->value.integer.step = (s64)data32->value.integer.step;
		/* Drop the rest of this field. */
	} else {
		/* Copy whole space of this field. */
		memcpy(&data->value, &data32->value, sizeof(data->value));
	}

	memcpy(&data->dimen, &data32->dimen, sizeof(data->dimen));
	memcpy(&data->reserved, &data32->reserved, sizeof(data->reserved));

	return 0;
}

static int serialize_to_elem_info_32(struct snd_ctl_file *ctl_file, void *dst,
				     void *src)
{
	struct snd_ctl_elem_info_32 *data32 = dst;
	struct snd_ctl_elem_info *data = src;

	data32->id = data->id;
	data32->type = data->type;
	data32->access = data->access;
	data32->count = data->count;
	data32->owner = data->owner;

	if (data->type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		data32->value.integer.min = (s32)data->value.integer.min;
		data32->value.integer.max = (s32)data->value.integer.max;
		data32->value.integer.step = (s32)data->value.integer.step;
		/* Drop rest of this field. */
	} else {
		/* Copy whole space of this field. */
		memcpy(&data32->value, &data->value, sizeof(data32->value));
	}

	memcpy(&data32->dimen, &data->dimen, sizeof(data32->dimen));
	memcpy(&data32->reserved, &data->reserved, sizeof(data32->reserved));

	return 0;
}

/*
 * Unfortunately, unlike the above structure, total size of '.id' and
 * '.indirect' is not multiples of 8 bytes (it's 68 bytes). Except for System V
 * ABI for i386 architecture, 'double-word' type has 8 bytes alignment. For such
 * architectures, 32 bit padding is needed.
 */
struct snd_ctl_elem_value_32 {
	struct snd_ctl_elem_id id;
	u32 indirect:1;
	u64 padding1:63;		/* For 8 bytes alignment of '.value'. */
	union {
		s32 integer[128];	/* long on ILP32. */
		u8 data[512];
		s64 integer64[64];
	} value;
	struct {
		s32 tv_sec;		/* long on ILP32. */
		s32 tv_nsec;		/* long on ILP32. */
	} tstamp;
	u8 reserved[128 - sizeof(s32) - sizeof(s32)];
} __packed;

static int get_type(struct snd_ctl_file *ctl_file, struct snd_ctl_elem_id *id,
		    snd_ctl_elem_type_t *type)
{
	struct snd_ctl_elem_info *info;
	int err;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	info->id = *id;

	err = snd_ctl_elem_info(ctl_file, info);
	if (err >= 0)
		*type = info->type;

	kfree(info);
	return err;
}

static int __maybe_unused deserialize_from_elem_value_32(
			struct snd_ctl_file *ctl_file, void *dst, void *src)
{
	struct snd_ctl_elem_value *data = dst;
	struct snd_ctl_elem_value_32 *data32 = src;
	snd_ctl_elem_type_t type;
	int err;

	err = get_type(ctl_file, &data32->id, &type);
	if (err < 0)
		return err;

	data->id = data32->id;
	data->indirect = data32->indirect;

	if (type == SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
	    type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		int i;
		for (i = 0; i < 128; ++i) {
			data->value.integer.value[i] =
						(s64)data32->value.integer[i];
		}
		/* Drop rest of this field. */
	} else {
		/* Copy whole space of this field. */
		memcpy(&data->value, &data32->value, sizeof(data->value));
	}

	data->tstamp.tv_sec = (s64)data32->tstamp.tv_sec;
	data->tstamp.tv_nsec = (s64)data32->tstamp.tv_nsec;

	return 0;
}

static int __maybe_unused serialize_to_elem_value_32(
			struct snd_ctl_file *ctl_file, void *dst, void *src)
{
	struct snd_ctl_elem_value_32 *data32 = dst;
	struct snd_ctl_elem_value *data = src;
	snd_ctl_elem_type_t type;
	int err;

	err = get_type(ctl_file, &data->id, &type);
	if (err < 0)
		return err;

	data32->id = data->id;
	data32->indirect = data->indirect;

	if (type == SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
	    type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		int i;
		for (i = 0; i < 128; ++i) {
			data32->value.integer[i] =
					(s32)data->value.integer.value[i];
		}
		/* Drop rest of this field. */
	} else {
		/* Copy whole space of this field. */
		memcpy(&data32->value, &data->value, sizeof(data32->value));
	}

	data32->tstamp.tv_sec = (s32)data->tstamp.tv_sec;
	data32->tstamp.tv_nsec = (s32)data->tstamp.tv_nsec;

	return 0;
}

/*
 * Unlikw any System V ABI for 32 bit architecture, ABI for i386 architecture has
 * different alignment (4 bytes) for double-word type. Thus offset of '.value'
 * member is multiples of 4 bytes.
 */
struct snd_ctl_elem_value_i386 {
	struct snd_ctl_elem_id id;
	u32 indirect:1;
	u32 padding:31;			/* For 4 bytes alignment of '.value'. */
	union {
		s32 integer[128];	/* long on ILP32. */
		u8 data[512];
		s64 integer64[64];
	} value;
	struct {
		s32 tv_sec;		/* long on ILP32. */
		s32 tv_nsec;		/* long on ILP32. */
	} tstamp;
	u8 reserved[128 - sizeof(s32) - sizeof(s32)];
} __packed;

static int __maybe_unused deserialize_from_elem_value_i386(
			struct snd_ctl_file *ctl_file, void *dst, void *src)
{
	struct snd_ctl_elem_value *data = dst;
	struct snd_ctl_elem_value_i386 *datai386 = src;
	snd_ctl_elem_type_t type;
	int err;

	err = get_type(ctl_file, &datai386->id, &type);
	if (err < 0)
		return err;

	data->id = datai386->id;
	data->indirect = datai386->indirect;

	if (type == SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
	    type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		int i;
		for (i = 0; i < 128; ++i) {
			data->value.integer.value[i] =
						(s64)datai386->value.integer[i];
		}
		/* Drop rest of this field. */
	} else {
		/* Copy whole space of this field. */
		memcpy(&data->value, &datai386->value, sizeof(data->value));
	}

	data->tstamp.tv_sec = (s64)datai386->tstamp.tv_sec;
	data->tstamp.tv_nsec = (s64)datai386->tstamp.tv_nsec;

	return 0;
}

static int __maybe_unused serialize_to_elem_value_i386(
			struct snd_ctl_file *ctl_file, void *dst, void *src)
{
	struct snd_ctl_elem_value_i386 *datai386 = dst;
	struct snd_ctl_elem_value *data = src;
	snd_ctl_elem_type_t type;
	int err;

	err = get_type(ctl_file, &data->id, &type);
	if (err < 0)
		return err;

	datai386->id = data->id;
	datai386->indirect = data->indirect;

	if (type == SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
	    type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		int i;
		for (i = 0; i < 128; ++i) {
			datai386->value.integer[i] =
					(s32)data->value.integer.value[i];
		}
		/* Drop rest of this field. */
	} else {
		/* Copy whole space of this field. */
		memcpy(&datai386->value, &data->value, sizeof(datai386->value));
	}

	datai386->tstamp.tv_sec = (s32)data->tstamp.tv_sec;
	datai386->tstamp.tv_nsec = (s32)data->tstamp.tv_nsec;

	return 0;
}

struct snd_ctl_elem_list32 {
	u32 offset;
	u32 space;
	u32 used;
	u32 count;
	u32 pids;
	unsigned char reserved[50];
} /* don't set packed attribute here */;

static int snd_ctl_elem_list_compat(struct snd_ctl_file *ctl_file,
				    struct snd_ctl_elem_list32 __user *data32)
{
	struct snd_ctl_elem_list __user *data;
	compat_caddr_t ptr;
	int err;

	data = compat_alloc_user_space(sizeof(*data));

	/* offset, space, used, count */
	if (copy_in_user(data, data32, 4 * sizeof(u32)))
		return -EFAULT;
	/* pids */
	if (get_user(ptr, &data32->pids) ||
	    put_user(compat_ptr(ptr), &data->pids))
		return -EFAULT;
	err = snd_ctl_elem_list(ctl_file, data);
	if (err < 0)
		return err;
	/* copy the result */
	if (copy_in_user(data32, data, 4 * sizeof(u32)))
		return -EFAULT;
	return 0;
}

/*
 * control element info
 * it uses union, so the things are not easy..
 */

struct snd_ctl_elem_info32 {
	struct snd_ctl_elem_id id; // the size of struct is same
	s32 type;
	u32 access;
	u32 count;
	s32 owner;
	union {
		struct {
			s32 min;
			s32 max;
			s32 step;
		} integer;
		struct {
			u64 min;
			u64 max;
			u64 step;
		} integer64;
		struct {
			u32 items;
			u32 item;
			char name[64];
			u64 names_ptr;
			u32 names_length;
		} enumerated;
		unsigned char reserved[128];
	} value;
	unsigned char reserved[64];
} __attribute__((packed));

static int snd_ctl_elem_info_compat(struct snd_ctl_file *ctl,
				    struct snd_ctl_elem_info32 __user *data32)
{
	struct snd_ctl_elem_info *data;
	int err;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (! data)
		return -ENOMEM;

	err = -EFAULT;
	/* copy id */
	if (copy_from_user(&data->id, &data32->id, sizeof(data->id)))
		goto error;
	/* we need to copy the item index.
	 * hope this doesn't break anything..
	 */
	if (get_user(data->value.enumerated.item, &data32->value.enumerated.item))
		goto error;

	err = snd_power_wait(ctl->card, SNDRV_CTL_POWER_D0);
	if (err < 0)
		goto error;
	err = snd_ctl_elem_info(ctl, data);
	if (err < 0)
		goto error;
	/* restore info to 32bit */
	err = -EFAULT;
	/* id, type, access, count */
	if (copy_to_user(&data32->id, &data->id, sizeof(data->id)) ||
	    copy_to_user(&data32->type, &data->type, 3 * sizeof(u32)))
		goto error;
	if (put_user(data->owner, &data32->owner))
		goto error;
	switch (data->type) {
	case SNDRV_CTL_ELEM_TYPE_BOOLEAN:
	case SNDRV_CTL_ELEM_TYPE_INTEGER:
		if (put_user(data->value.integer.min, &data32->value.integer.min) ||
		    put_user(data->value.integer.max, &data32->value.integer.max) ||
		    put_user(data->value.integer.step, &data32->value.integer.step))
			goto error;
		break;
	case SNDRV_CTL_ELEM_TYPE_INTEGER64:
		if (copy_to_user(&data32->value.integer64,
				 &data->value.integer64,
				 sizeof(data->value.integer64)))
			goto error;
		break;
	case SNDRV_CTL_ELEM_TYPE_ENUMERATED:
		if (copy_to_user(&data32->value.enumerated,
				 &data->value.enumerated,
				 sizeof(data->value.enumerated)))
			goto error;
		break;
	default:
		break;
	}
	err = 0;
 error:
	kfree(data);
	return err;
}

/* read / write */
struct snd_ctl_elem_value32 {
	struct snd_ctl_elem_id id;
	unsigned int indirect;	/* bit-field causes misalignment */
        union {
		s32 integer[128];
		unsigned char data[512];
#ifndef CONFIG_X86_64
		s64 integer64[64];
#endif
        } value;
        unsigned char reserved[128];
};

#ifdef CONFIG_X86_X32
/* x32 has a different alignment for 64bit values from ia32 */
struct snd_ctl_elem_value_x32 {
	struct snd_ctl_elem_id id;
	unsigned int indirect;	/* bit-field causes misalignment */
	union {
		s32 integer[128];
		unsigned char data[512];
		s64 integer64[64];
	} value;
	unsigned char reserved[128];
};
#endif /* CONFIG_X86_X32 */

/* get the value type and count of the control */
static int get_ctl_type(struct snd_card *card, struct snd_ctl_elem_id *id,
			int *countp)
{
	struct snd_kcontrol *kctl;
	struct snd_ctl_elem_info *info;
	int err;

	down_read(&card->controls_rwsem);
	kctl = snd_ctl_find_id(card, id);
	if (! kctl) {
		up_read(&card->controls_rwsem);
		return -ENOENT;
	}
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL) {
		up_read(&card->controls_rwsem);
		return -ENOMEM;
	}
	info->id = *id;
	err = kctl->info(kctl, info);
	up_read(&card->controls_rwsem);
	if (err >= 0) {
		err = info->type;
		*countp = info->count;
	}
	kfree(info);
	return err;
}

static int get_elem_size(int type, int count)
{
	switch (type) {
	case SNDRV_CTL_ELEM_TYPE_INTEGER64:
		return sizeof(s64) * count;
	case SNDRV_CTL_ELEM_TYPE_ENUMERATED:
		return sizeof(int) * count;
	case SNDRV_CTL_ELEM_TYPE_BYTES:
		return 512;
	case SNDRV_CTL_ELEM_TYPE_IEC958:
		return sizeof(struct snd_aes_iec958);
	default:
		return -1;
	}
}

static int copy_ctl_value_from_user(struct snd_card *card,
				    struct snd_ctl_elem_value *data,
				    void __user *userdata,
				    void __user *valuep,
				    int *typep, int *countp)
{
	struct snd_ctl_elem_value32 __user *data32 = userdata;
	int i, type, size;
	int uninitialized_var(count);
	unsigned int indirect;

	if (copy_from_user(&data->id, &data32->id, sizeof(data->id)))
		return -EFAULT;
	if (get_user(indirect, &data32->indirect))
		return -EFAULT;
	if (indirect)
		return -EINVAL;
	type = get_ctl_type(card, &data->id, &count);
	if (type < 0)
		return type;

	if (type == SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
	    type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		for (i = 0; i < count; i++) {
			s32 __user *intp = valuep;
			int val;
			if (get_user(val, &intp[i]))
				return -EFAULT;
			data->value.integer.value[i] = val;
		}
	} else {
		size = get_elem_size(type, count);
		if (size < 0) {
			dev_err(card->dev, "snd_ioctl32_ctl_elem_value: unknown type %d\n", type);
			return -EINVAL;
		}
		if (copy_from_user(data->value.bytes.data, valuep, size))
			return -EFAULT;
	}

	*typep = type;
	*countp = count;
	return 0;
}

/* restore the value to 32bit */
static int copy_ctl_value_to_user(void __user *userdata,
				  void __user *valuep,
				  struct snd_ctl_elem_value *data,
				  int type, int count)
{
	int i, size;

	if (type == SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
	    type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		for (i = 0; i < count; i++) {
			s32 __user *intp = valuep;
			int val;
			val = data->value.integer.value[i];
			if (put_user(val, &intp[i]))
				return -EFAULT;
		}
	} else {
		size = get_elem_size(type, count);
		if (copy_to_user(valuep, data->value.bytes.data, size))
			return -EFAULT;
	}
	return 0;
}

static int ctl_elem_read_user(struct snd_card *card,
			      void __user *userdata, void __user *valuep)
{
	struct snd_ctl_elem_value *data;
	int err, type, count;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	err = copy_ctl_value_from_user(card, data, userdata, valuep,
				       &type, &count);
	if (err < 0)
		goto error;

	err = snd_power_wait(card, SNDRV_CTL_POWER_D0);
	if (err < 0)
		goto error;
	err = snd_ctl_elem_read(card, data);
	if (err < 0)
		goto error;
	err = copy_ctl_value_to_user(userdata, valuep, data, type, count);
 error:
	kfree(data);
	return err;
}

static int ctl_elem_write_user(struct snd_ctl_file *file,
			       void __user *userdata, void __user *valuep)
{
	struct snd_ctl_elem_value *data;
	struct snd_card *card = file->card;
	int err, type, count;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	err = copy_ctl_value_from_user(card, data, userdata, valuep,
				       &type, &count);
	if (err < 0)
		goto error;

	err = snd_power_wait(card, SNDRV_CTL_POWER_D0);
	if (err < 0)
		goto error;
	err = snd_ctl_elem_write(card, file, data);
	if (err < 0)
		goto error;
	err = copy_ctl_value_to_user(userdata, valuep, data, type, count);
 error:
	kfree(data);
	return err;
}

static int snd_ctl_elem_read_user_compat(struct snd_card *card,
					 struct snd_ctl_elem_value32 __user *data32)
{
	return ctl_elem_read_user(card, data32, &data32->value);
}

static int snd_ctl_elem_write_user_compat(struct snd_ctl_file *file,
					  struct snd_ctl_elem_value32 __user *data32)
{
	return ctl_elem_write_user(file, data32, &data32->value);
}

#ifdef CONFIG_X86_X32
static int snd_ctl_elem_read_user_x32(struct snd_card *card,
				      struct snd_ctl_elem_value_x32 __user *data32)
{
	return ctl_elem_read_user(card, data32, &data32->value);
}

static int snd_ctl_elem_write_user_x32(struct snd_ctl_file *file,
				       struct snd_ctl_elem_value_x32 __user *data32)
{
	return ctl_elem_write_user(file, data32, &data32->value);
}
#endif /* CONFIG_X86_X32 */

/* add or replace a user control */
static int snd_ctl_elem_add_compat(struct snd_ctl_file *file,
				   struct snd_ctl_elem_info32 __user *data32,
				   int replace)
{
	struct snd_ctl_elem_info *data;
	int err;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (! data)
		return -ENOMEM;

	err = -EFAULT;
	/* id, type, access, count */ \
	if (copy_from_user(&data->id, &data32->id, sizeof(data->id)) ||
	    copy_from_user(&data->type, &data32->type, 3 * sizeof(u32)))
		goto error;
	if (get_user(data->owner, &data32->owner) ||
	    get_user(data->type, &data32->type))
		goto error;
	switch (data->type) {
	case SNDRV_CTL_ELEM_TYPE_BOOLEAN:
	case SNDRV_CTL_ELEM_TYPE_INTEGER:
		if (get_user(data->value.integer.min, &data32->value.integer.min) ||
		    get_user(data->value.integer.max, &data32->value.integer.max) ||
		    get_user(data->value.integer.step, &data32->value.integer.step))
			goto error;
		break;
	case SNDRV_CTL_ELEM_TYPE_INTEGER64:
		if (copy_from_user(&data->value.integer64,
				   &data32->value.integer64,
				   sizeof(data->value.integer64)))
			goto error;
		break;
	case SNDRV_CTL_ELEM_TYPE_ENUMERATED:
		if (copy_from_user(&data->value.enumerated,
				   &data32->value.enumerated,
				   sizeof(data->value.enumerated)))
			goto error;
		data->value.enumerated.names_ptr =
			(uintptr_t)compat_ptr(data->value.enumerated.names_ptr);
		break;
	default:
		break;
	}
	err = snd_ctl_elem_add(file, data, replace);
 error:
	kfree(data);
	return err;
}  

enum {
	SNDRV_CTL_IOCTL_ELEM_LIST32 = _IOWR('U', 0x10, struct snd_ctl_elem_list32),
	SNDRV_CTL_IOCTL_ELEM_INFO32 = _IOWR('U', 0x11, struct snd_ctl_elem_info32),
	SNDRV_CTL_IOCTL_ELEM_READ32 = _IOWR('U', 0x12, struct snd_ctl_elem_value32),
	SNDRV_CTL_IOCTL_ELEM_WRITE32 = _IOWR('U', 0x13, struct snd_ctl_elem_value32),
	SNDRV_CTL_IOCTL_ELEM_ADD32 = _IOWR('U', 0x17, struct snd_ctl_elem_info32),
	SNDRV_CTL_IOCTL_ELEM_REPLACE32 = _IOWR('U', 0x18, struct snd_ctl_elem_info32),
#ifdef CONFIG_X86_X32
	SNDRV_CTL_IOCTL_ELEM_READ_X32 = _IOWR('U', 0x12, struct snd_ctl_elem_value_x32),
	SNDRV_CTL_IOCTL_ELEM_WRITE_X32 = _IOWR('U', 0x13, struct snd_ctl_elem_value_x32),
#endif /* CONFIG_X86_X32 */
};

static long snd_ctl_ioctl_compat(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	static const struct {
		unsigned int cmd;
		int (*deserialize)(struct snd_ctl_file *ctl_file, void *dst,
				   void *src);
		int (*func)(struct snd_ctl_file *ctl_file, void *buf);
		int (*serialize)(struct snd_ctl_file *ctl_file, void *dst,
				 void *src);
		unsigned int orig_cmd;
	} handlers[] = {
		{ 0, NULL, NULL, NULL, 0, },
	};
	struct snd_ctl_file *ctl;
	void __user *argp = compat_ptr(arg);
	void *buf, *data;
	unsigned int size;
	int i;
	int err;

	ctl = file->private_data;
	if (snd_BUG_ON(!ctl || !ctl->card))
		return -ENXIO;

	switch (cmd) {
	case SNDRV_CTL_IOCTL_ELEM_LIST32:
		return snd_ctl_elem_list_compat(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_INFO32:
		return snd_ctl_elem_info_compat(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_READ32:
		return snd_ctl_elem_read_user_compat(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_WRITE32:
		return snd_ctl_elem_write_user_compat(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_ADD32:
		return snd_ctl_elem_add_compat(ctl, argp, 0);
	case SNDRV_CTL_IOCTL_ELEM_REPLACE32:
		return snd_ctl_elem_add_compat(ctl, argp, 1);
#ifdef CONFIG_X86_X32
	case SNDRV_CTL_IOCTL_ELEM_READ_X32:
		return snd_ctl_elem_read_user_x32(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_WRITE_X32:
		return snd_ctl_elem_write_user_x32(ctl, argp);
#endif /* CONFIG_X86_X32 */
	}

	for (i = 0; i < ARRAY_SIZE(handlers); ++i) {
		if (handlers[i].cmd == cmd)
			break;
	}
	if (i == ARRAY_SIZE(handlers)) {
		struct snd_kctl_ioctl *p;

		down_read(&snd_ioctl_rwsem);
		list_for_each_entry(p, &snd_control_compat_ioctls, list) {
			if (p->fioctl) {
				err = p->fioctl(ctl->card, ctl, cmd, arg);
				if (err != -ENOIOCTLCMD) {
					up_read(&snd_ioctl_rwsem);
					return err;
				}
			}
		}
		up_read(&snd_ioctl_rwsem);

		return snd_ctl_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
	}

	/* Allocate a buffer to convert layout of structure for native ABI. */
	buf = kzalloc(_IOC_SIZE(handlers[i].orig_cmd), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Allocate an alternative buffer to copy from/to user space. */
	size = _IOC_SIZE(handlers[i].cmd);
	data = kzalloc(size, GFP_KERNEL);
	if (!data) {
		kfree(buf);
		return -ENOMEM;
	}

	if (handlers[i].cmd & IOC_IN) {
		if (copy_from_user(data, compat_ptr(arg), size)) {
			err = -EFAULT;
			goto end;
		}
	}

	err = handlers[i].deserialize(ctl, buf, data);
	if (err < 0)
		goto end;

	err = handlers[i].func(ctl, buf);
	if (err < 0)
		goto end;

	err = handlers[i].serialize(ctl, data, buf);
	if (err >= 0) {
		if (handlers[i].cmd & IOC_OUT) {
			if (copy_to_user(compat_ptr(arg), data, size))
				err = -EFAULT;
		}
	}
end:
	kfree(data);
	kfree(buf);
	return err;
}
