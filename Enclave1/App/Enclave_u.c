#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_secure_add_t {
	double ms_retval;
	double ms_a;
	double ms_b;
} ms_secure_add_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t secure_add(sgx_enclave_id_t eid, double* retval, double a, double b)
{
	sgx_status_t status;
	ms_secure_add_t ms;
	ms.ms_a = a;
	ms.ms_b = b;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

