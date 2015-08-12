#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/err.h>
#include <linux/seq_file.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jstancek");
MODULE_DESCRIPTION("excercise sha 256/512");

static char *filename;
module_param(filename, charp, 0000);
MODULE_PARM_DESC(filename, "name of data file");

static size_t datalen;
static u8 *data;

static u8 digest[4096];
static int digest_size;

static struct public_key_signature *make_digest(
		const char *hashname,
		const void *mod,
		unsigned long modlen,
		int chunksize)
{
	struct public_key_signature *pks;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t digest_size, desc_size;
	int ret;

	pr_devel("==>%s()\n", __func__);

	tfm = crypto_alloc_shash(hashname, 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? ERR_PTR(-ENOPKG) : ERR_CAST(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	digest_size = crypto_shash_digestsize(tfm);

	/* We allocate the hash operational data storage on the end of our
	 * context data and the digest output buffer on the end of that.
	 */
	ret = -ENOMEM;
	pks = kzalloc(digest_size + sizeof(*pks) + desc_size, GFP_KERNEL);
	if (!pks)
		goto error_no_pks;

	pks->pkey_hash_algo     = -1;
	pks->digest             = (u8 *)pks + sizeof(*pks) + desc_size;
	pks->digest_size        = digest_size;

	desc = (void *)pks + sizeof(*pks);
	desc->tfm   = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;


	if (chunksize != 0) {
		while (modlen > chunksize) {
			ret = crypto_shash_update(desc, mod, chunksize);
			if (ret < 0)
				goto error;
			mod += chunksize;
			modlen -= chunksize;
		}
	}

	ret = crypto_shash_finup(desc, mod, modlen, pks->digest);
	if (ret < 0)
		goto error;

	crypto_free_shash(tfm);
	pr_devel("<==%s() = ok\n", __func__);

	return pks;

error:
	//mpi_free(pks->rsa.s);
	kfree(pks);
error_no_pks:
	crypto_free_shash(tfm);
	pr_devel("<==%s() = %d\n", __func__, ret);
	return ERR_PTR(ret);
}

static int read_testfile(u8 **datap, size_t *datalenp)
{
	struct file* filp = NULL;
	struct kstat stat;
	loff_t pos;
	ssize_t bytes = 0;
	int err = 0;

	*datap = NULL;
	*datalenp = 0;

	filp = filp_open(filename, O_RDONLY, 0);
	if(IS_ERR(filp)) {
		err = PTR_ERR(filp);
		goto out;
	}

	err = vfs_getattr(&filp->f_path, &stat);
	if (err)
		goto free_file;

	datalen = stat.size;
	if (datalen == 0) {
		err = -EINVAL;
		goto free_file;
	}

	data = vmalloc(datalen);
	if (!data) {
		err = -ENOMEM;
		goto free_file;
	}

	pos = 0;
	while (pos < stat.size) {
		bytes = kernel_read(filp, pos, (char *)(data) + pos,
				stat.size - pos);
		if (bytes < 0) {
			err = bytes;
			vfree(data);
			goto free_file;
		}
		if (bytes == 0)
			break;
		pos += bytes;
	}

	*datap = data;
	*datalenp = datalen;

free_file:
	filp_close(filp, NULL);

out:
	return err;
}

ssize_t shatest_proc_write(struct file *file, const char __user *buf, size_t size, loff_t *off)
{
	char mybuf[256];
	char hashname[64];
	int length, chunksize, offset;
	struct public_key_signature *pks = NULL;

	if (copy_from_user(mybuf, buf, size)) {
		printk("error copy_from_user\n");
		return -EFAULT;
	}

	if (sscanf(mybuf, "%s %d %d %d", hashname, &length, &chunksize, &offset) != 4) {
		printk("error sscanf\n");
		return -EFAULT;
	}

	pks = make_digest(hashname, data + offset, length, chunksize);
	if (IS_ERR(pks)) {
		printk("error digest: %ld\n", PTR_ERR(pks));
		return PTR_ERR(pks);
	}
	digest_size = pks->digest_size;
	memcpy(digest, pks->digest, digest_size);

	if (pks) {
		//mpi_free(pks->rsa.s);
		kfree(pks);
	}

	return size;
}

int shatest_proc_read(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < digest_size; i++)
		seq_printf(m, "%02x", digest[i]);
	seq_printf(m, "\n");
	return 0;
}

int shatest_proc_open(struct inode *inode, struct file *file){
	return single_open(file, shatest_proc_read, NULL);
}

struct file_operations fops = {
	.open = shatest_proc_open,
	.read = seq_read,
	.write = shatest_proc_write,
	.release = single_release,
};

static int __init shatest_init(void)
{
	int ret = 0;
	struct proc_dir_entry *myproc;

	if (filename == NULL) {
		printk("Error: no filename provided\n");
		ret = -EINVAL;
		goto out;
	}

	myproc = proc_create("sha_test", 0666, NULL, &fops);
	if (myproc == NULL) {
		ret = -EFAULT;
		printk("error making proc file\n");
		goto out;
	}

	ret = read_testfile(&data, &datalen);
	if (ret) {
		printk("error reading file\n");
		remove_proc_entry("sha_test", NULL);
		goto out;
	}

	printk("sha_test module loaded\n");
out:
	return ret;
}

static void __exit shatest_cleanup(void)
{
	if (data)
		vfree(data);

	remove_proc_entry("sha_test", NULL);
	printk("sha_test module unloaded\n");
}

module_init(shatest_init);
module_exit(shatest_cleanup);

