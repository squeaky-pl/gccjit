#include <libgccjit.h>
#include <stdlib.h>

typedef int (*fn_type) (int, int);

int main()
{
  gcc_jit_context *ctxt = gcc_jit_context_acquire();

  gcc_jit_context_set_bool_option (
    ctxt,
    GCC_JIT_BOOL_OPTION_DUMP_INITIAL_TREE,
    1);

  gcc_jit_context_set_bool_option (
    ctxt,
    GCC_JIT_BOOL_OPTION_DUMP_GENERATED_CODE,
    1);

  gcc_jit_type *int_type = gcc_jit_context_get_type (ctxt, GCC_JIT_TYPE_INT);

  gcc_jit_param *param_i = gcc_jit_context_new_param (ctxt, NULL, int_type, "i");
  gcc_jit_param *param_z = gcc_jit_context_new_param (ctxt, NULL, int_type, "z");

  gcc_jit_param* params[] = {param_i, param_z};

  gcc_jit_function *func =
  gcc_jit_context_new_function (ctxt, NULL,
                                GCC_JIT_FUNCTION_EXPORTED,
                                int_type,
                                "square",
                                2, params,
                                0);

  gcc_jit_block *block = gcc_jit_function_new_block (func, NULL);

  gcc_jit_rvalue *multiplication =
  gcc_jit_context_new_binary_op (
    ctxt, NULL,
    GCC_JIT_BINARY_OP_MULT, int_type,
    gcc_jit_param_as_rvalue (param_i),
    gcc_jit_param_as_rvalue (param_i));

  gcc_jit_rvalue *addition =
  gcc_jit_context_new_binary_op (
    ctxt, NULL,
    GCC_JIT_BINARY_OP_PLUS, int_type,
    multiplication,
    gcc_jit_param_as_rvalue(param_z)
  );

  gcc_jit_block_end_with_return (block, NULL, addition);

  gcc_jit_result *result;
  result = gcc_jit_context_compile (ctxt);

  gcc_jit_context_release (ctxt);

  void *fn_ptr = gcc_jit_result_get_code (result, "square");
  if(!fn_ptr)
    abort();

  fn_type square = (fn_type)fn_ptr;
  printf ("result: %d", square (5, 1));

  gcc_jit_result_release (result);
}
