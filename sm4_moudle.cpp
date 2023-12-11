#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "sm4.h"

inline int min(int a, int b) {
    return (a <= b) ? a : b;
}

static bool parse_args_ecb(PyObject *args, Py_buffer *key, Py_buffer *src) {
    if (!PyArg_ParseTuple(args, "y*y*", key, src)) {
        return false;
    }
    if (key->len == 16) {
        return true;
    }
    PyErr_SetString(PyExc_ValueError, "The key must have length of 16 bytes.");
    PyBuffer_Release(key);
    PyBuffer_Release(src);
    return false;
}

static PyObject *method_encrypt_ecb(PyObject *self, PyObject *args) {
    Py_buffer key, src;
    if (!parse_args_ecb(args, &key, &src)) {
        return NULL;
    }
    bytes out = (bytes)malloc(src.len + 16);
    Py_ssize_t outlen = encrypt_ecb(out, (bytes)key.buf, (bytes)src.buf, src.len);
    PyObject *result = PyBytes_FromStringAndSize((char *)out, outlen);

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    return result;
}

static PyObject *method_decrypt_ecb(PyObject *self, PyObject *args) {
    Py_buffer key, src;
    if (!parse_args_ecb(args, &key, &src)) {
        return NULL;
    }
    bytes out = (bytes)malloc(src.len);
    Py_ssize_t outlen = decrypt_ecb(out, (bytes)key.buf, (bytes)src.buf, src.len);

    PyObject *result = NULL;
    if (outlen >= 0) {
        result = PyBytes_FromStringAndSize((char *)out, outlen);
    } else {
        PyErr_SetString(PyExc_ValueError, "Decrypt failed.");
    }

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    return result;
}

static bool parse_args_cbc(PyObject *args, Py_buffer *key, Py_buffer *src, Py_buffer *iv) {
    memset(iv, 0, sizeof(Py_buffer));
    if (!PyArg_ParseTuple(args, "y*y*y*", key, src, iv)) {
        return false;
    }
    if (key->len == 16 && iv->len == 16) {
        return true;
    }
    PyErr_SetString(PyExc_ValueError,
                    (key->len != 16)
                    ? "The key must have length of 16 bytes."
                    : "The iv must have length of 16 bytes.");
    PyBuffer_Release(key);
    PyBuffer_Release(src);
    PyBuffer_Release(iv);
    return false;
}

static PyObject *method_encrypt_cbc(PyObject *self, PyObject *args) {
    Py_buffer key, src, iv;
    if (!parse_args_cbc(args, &key, &src, &iv)) {
        return NULL;
    }
    bytes out = (bytes)malloc(src.len + 16);
    Py_ssize_t outlen = encrypt_cbc(out, (bytes)key.buf, (bytes)src.buf, src.len, (bytes)iv.buf);
    PyObject *result = PyBytes_FromStringAndSize((char *)out, outlen);

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    PyBuffer_Release(&iv);
    return result;
}

static PyObject *method_decrypt_cbc(PyObject *self, PyObject *args) {
    Py_buffer key, src, iv;
    if (!parse_args_cbc(args, &key, &src, &iv)) {
        return NULL;
    }
    bytes out = (bytes)malloc(src.len);
    Py_ssize_t outlen = decrypt_cbc(out, (bytes)key.buf, (bytes)src.buf, src.len, (bytes)iv.buf);

    PyObject *result = NULL;
    if (outlen >= 0) {
        result = PyBytes_FromStringAndSize((char *)out, outlen);
    } else {
        PyErr_SetString(PyExc_ValueError, "Decrypt failed.");
    }

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    PyBuffer_Release(&iv);
    return result;
}

static bool parse_args_ctr(PyObject *args, Py_buffer *key, Py_buffer *src, Py_buffer *iv) {
    memset(iv, 0, sizeof(Py_buffer));
    if (!PyArg_ParseTuple(args, "y*y*y*", key, src, iv)) {
        return false;
    }
    if (key->len == 16 && iv->len <= 16) {
        return true;
    }
    PyErr_SetString(PyExc_ValueError,
                    (key->len != 16)
                    ? "The key must have length of 16 bytes."
                    : "The iv must have length from 0 to 16 bytes.");
    PyBuffer_Release(key);
    PyBuffer_Release(src);
    PyBuffer_Release(iv);
    return false;
}

static PyObject *method_encrypt_ctr(PyObject *self, PyObject *args) {
    Py_buffer key, src, iv;
    if (!parse_args_ctr(args, &key, &src, &iv)) {
        return NULL;
    }
    bytes out = (bytes)malloc(src.len);
    Py_ssize_t outlen = encrypt_ctr(out, (bytes)key.buf, (bytes)src.buf, src.len, (bytes)iv.buf, (int)iv.len);
    PyObject *result = PyBytes_FromStringAndSize((char *)out, outlen);

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    PyBuffer_Release(&iv);
    return result;
}

static bool parse_args_egcm(PyObject *args, Py_buffer *key, Py_buffer *src,
                            Py_buffer *iv, Py_buffer *aad, int *taglen) {
    if (!PyArg_ParseTuple(args, "y*y*y*y*i", key, src, iv, aad, taglen)) {
        return false;
    }
    if (key->len == 16) {
        return true;
    }
    PyErr_SetString(PyExc_ValueError, "The key must have length of 16 bytes.");
    PyBuffer_Release(key);
    PyBuffer_Release(src);
    PyBuffer_Release(aad);
    PyBuffer_Release(iv);
    return false;
}

static PyObject *method_encrypt_gcm(PyObject *self, PyObject *args) {
    Py_buffer key, src, iv, aad;
    int taglen;
    if (!parse_args_egcm(args, &key, &src, &iv, &aad, &taglen)) {
        return NULL;
    }
    byte tag[16];
    taglen = min(16, taglen);
    bytes out = (bytes)malloc(src.len);
    Py_ssize_t outlen = encrypt_gcm(out, tag, (bytes)key.buf, (bytes)src.buf, src.len,
                                    (bytes)iv.buf, (int)iv.len, (bytes)aad.buf, (int)aad.len);
    PyObject *result = PyTuple_New(2);
    PyTuple_SetItem(result, 0, PyBytes_FromStringAndSize((char *)out, outlen));
    PyTuple_SetItem(result, 1, PyBytes_FromStringAndSize((char *)tag, taglen));

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    PyBuffer_Release(&aad);
    PyBuffer_Release(&iv);
    return result;
}

static bool parse_args_dgcm(PyObject *args, Py_buffer *key, Py_buffer *src,
                            Py_buffer *iv, Py_buffer *aad, Py_buffer *tag) {
    if (!PyArg_ParseTuple(args, "y*y*y*y*y*", key, src, iv, aad, tag)) {
        return false;
    }
    if (key->len == 16) {
        return true;
    }
    PyErr_SetString(PyExc_ValueError, "The key must have length of 16 bytes.");
    PyBuffer_Release(key);
    PyBuffer_Release(src);
    PyBuffer_Release(aad);
    PyBuffer_Release(tag);
    PyBuffer_Release(iv);
    return false;
}

static PyObject *method_decrypt_gcm(PyObject *self, PyObject *args) {
    Py_buffer key, src, iv, aad, tag;
    if (!parse_args_dgcm(args, &key, &src, &iv, &aad, &tag)) {
        return NULL;
    }
    bytes out = (bytes)malloc(src.len);
    Py_ssize_t outlen = decrypt_gcm(out, (bytes)key.buf, (bytes)src.buf, src.len,
                                    (bytes)iv.buf, (int)iv.len, (bytes)aad.buf, (int)aad.len,
                                    (bytes)tag.buf, (int)tag.len);
    PyObject *result = NULL;
    if (outlen >= 0) {
        result = PyBytes_FromStringAndSize((char *)out, outlen);
    } else {
        PyErr_SetString(PyExc_ValueError, "Tag mismatching.");
    }

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    PyBuffer_Release(&aad);
    PyBuffer_Release(&tag);
    PyBuffer_Release(&iv);
    return result;
}

static PyObject *method_encrypt_ccm(PyObject *self, PyObject *args) {
    Py_buffer key, src, iv, aad;
    int taglen;
    if (!parse_args_egcm(args, &key, &src, &iv, &aad, &taglen)) {
        return NULL;
    }
    if ((size_t)src.len >= (1LLU << (15 - iv.len) * 8)) {
        PyErr_SetString(PyExc_ValueError, "The data or iv is too long.");
        return NULL;
    }

    byte tag[16];
    taglen = min(16, taglen);
    bytes out = (bytes)malloc(src.len);
    Py_ssize_t outlen = encrypt_ccm(out, tag, (bytes)key.buf, (bytes)src.buf, src.len,
                                    (bytes)iv.buf, (int)iv.len, (bytes)aad.buf, (int)aad.len, taglen);
    PyObject *result = PyTuple_New(2);
    PyTuple_SetItem(result, 0, PyBytes_FromStringAndSize((char *)out, outlen));
    PyTuple_SetItem(result, 1, PyBytes_FromStringAndSize((char *)tag, taglen));

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    PyBuffer_Release(&aad);
    PyBuffer_Release(&iv);
    return result;
}

static PyObject *method_decrypt_ccm(PyObject *self, PyObject *args) {
    Py_buffer key, src, iv, aad, tag;
    if (!parse_args_dgcm(args, &key, &src, &iv, &aad, &tag)) {
        return NULL;
    }
    if ((size_t)src.len >= (1LLU << (15 - iv.len) * 8)) {
        PyErr_SetString(PyExc_ValueError, "The data or iv is too long.");
        return NULL;
    }

    bytes out = (bytes)malloc(src.len);
    Py_ssize_t outlen = decrypt_ccm(out, (bytes)key.buf, (bytes)src.buf, src.len,
                                    (bytes)iv.buf, (int)iv.len, (bytes)aad.buf, (int)aad.len,
                                    (bytes)tag.buf, (int)tag.len);
    PyObject *result = NULL;
    if (outlen >= 0) {
        result = PyBytes_FromStringAndSize((char *)out, outlen);
    } else {
        PyErr_SetString(PyExc_ValueError, "Tag mismatching.");
    }

    free(out);
    PyBuffer_Release(&key);
    PyBuffer_Release(&src);
    PyBuffer_Release(&aad);
    PyBuffer_Release(&tag);
    PyBuffer_Release(&iv);
    return result;
}

static PyMethodDef SM4Methods[] = {
    {"encrypt_ecb", method_encrypt_ecb, METH_VARARGS, "SM4-ECB block encryption."},
    {"decrypt_ecb", method_decrypt_ecb, METH_VARARGS, "SM4-ECB block decryption."},
    {"encrypt_cbc", method_encrypt_cbc, METH_VARARGS, "SM4-CBC block encryption."},
    {"decrypt_cbc", method_decrypt_cbc, METH_VARARGS, "SM4-CBC block decryption."},
    {"encrypt_ctr", method_encrypt_ctr, METH_VARARGS, "SM4-CTR encryption and decryption."},
    {"encrypt_gcm", method_encrypt_gcm, METH_VARARGS, "SM4-GCM block encryption."},
    {"decrypt_gcm", method_decrypt_gcm, METH_VARARGS, "SM4-GCM block decryption."},
    {"encrypt_ccm", method_encrypt_ccm, METH_VARARGS, "SM4-CCM block encryption."},
    {"decrypt_ccm", method_decrypt_ccm, METH_VARARGS, "SM4-CCM block decryption."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sm4module = {
    PyModuleDef_HEAD_INIT,
    "_sm4",
    "SM4 encrypt and decrypt.",
    -1,
    SM4Methods
};

PyMODINIT_FUNC PyInit__sm4(void) {
    return PyModule_Create(&sm4module);
}
