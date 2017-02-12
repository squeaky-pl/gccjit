import enum

from cffi import FFI

ffi = FFI()
ffi.cdef("""
enum gcc_jit_bool_option
{

  GCC_JIT_BOOL_OPTION_DEBUGINFO,
  GCC_JIT_BOOL_OPTION_DUMP_INITIAL_TREE,
  GCC_JIT_BOOL_OPTION_DUMP_INITIAL_GIMPLE,
  GCC_JIT_BOOL_OPTION_DUMP_GENERATED_CODE,
  GCC_JIT_BOOL_OPTION_DUMP_SUMMARY,
  GCC_JIT_BOOL_OPTION_DUMP_EVERYTHING,
  GCC_JIT_BOOL_OPTION_SELFCHECK_GC,
  GCC_JIT_BOOL_OPTION_KEEP_INTERMEDIATES,

  GCC_JIT_NUM_BOOL_OPTIONS
};

    typedef ... gcc_jit_context;

    gcc_jit_context* gcc_jit_context_acquire (void);

    void gcc_jit_context_set_bool_option (gcc_jit_context *ctxt,
                                  enum gcc_jit_bool_option opt,
                                  int value);

enum gcc_jit_int_option
{
  GCC_JIT_INT_OPTION_OPTIMIZATION_LEVEL,
  GCC_JIT_NUM_INT_OPTIONS
};

void gcc_jit_context_set_int_option (gcc_jit_context *ctxt,
    enum gcc_jit_int_option opt,
    int value);

    typedef ... gcc_jit_type;

enum gcc_jit_types
{
  GCC_JIT_TYPE_VOID,
  GCC_JIT_TYPE_VOID_PTR,
  GCC_JIT_TYPE_BOOL,
  GCC_JIT_TYPE_CHAR,
  GCC_JIT_TYPE_SIGNED_CHAR,
  GCC_JIT_TYPE_UNSIGNED_CHAR,
  GCC_JIT_TYPE_SHORT,
  GCC_JIT_TYPE_UNSIGNED_SHORT,
  GCC_JIT_TYPE_INT,
  GCC_JIT_TYPE_UNSIGNED_INT,
  GCC_JIT_TYPE_LONG,
  GCC_JIT_TYPE_UNSIGNED_LONG,
  GCC_JIT_TYPE_LONG_LONG,
  GCC_JIT_TYPE_UNSIGNED_LONG_LONG,
  GCC_JIT_TYPE_FLOAT,
  GCC_JIT_TYPE_DOUBLE,
  GCC_JIT_TYPE_LONG_DOUBLE,
  GCC_JIT_TYPE_CONST_CHAR_PTR,
  GCC_JIT_TYPE_SIZE_T,
  GCC_JIT_TYPE_FILE_PTR,
  GCC_JIT_TYPE_COMPLEX_FLOAT,
  GCC_JIT_TYPE_COMPLEX_DOUBLE,
  GCC_JIT_TYPE_COMPLEX_LONG_DOUBLE

};

typedef ... gcc_jit_location;
typedef ... gcc_jit_param;

    gcc_jit_type *gcc_jit_context_get_type (gcc_jit_context *ctxt,
        enum gcc_jit_types type_);

    gcc_jit_param *gcc_jit_context_new_param (gcc_jit_context *ctxt,
        gcc_jit_location *loc,
        gcc_jit_type *type,
        const char *name);

enum gcc_jit_function_kind
{
  GCC_JIT_FUNCTION_EXPORTED,
  GCC_JIT_FUNCTION_INTERNAL,
  GCC_JIT_FUNCTION_IMPORTED,
  GCC_JIT_FUNCTION_ALWAYS_INLINE
};

typedef ... gcc_jit_function;

    gcc_jit_function *
    gcc_jit_context_new_function (gcc_jit_context *ctxt,
      gcc_jit_location *loc,
      enum gcc_jit_function_kind kind,
      gcc_jit_type *return_type,
      const char *name,
      int num_params,
      gcc_jit_param **params,
      int is_variadic);

typedef ... gcc_jit_block;

gcc_jit_block *
gcc_jit_function_new_block (gcc_jit_function *func,
    const char *name);

typedef ... gcc_jit_rvalue;

enum gcc_jit_binary_op
{
  GCC_JIT_BINARY_OP_PLUS,
  GCC_JIT_BINARY_OP_MINUS,
  GCC_JIT_BINARY_OP_MULT,
  GCC_JIT_BINARY_OP_DIVIDE,
  GCC_JIT_BINARY_OP_MODULO,
  GCC_JIT_BINARY_OP_BITWISE_AND,
  GCC_JIT_BINARY_OP_BITWISE_XOR,
  GCC_JIT_BINARY_OP_BITWISE_OR,
  GCC_JIT_BINARY_OP_LOGICAL_AND,
  GCC_JIT_BINARY_OP_LOGICAL_OR,
  GCC_JIT_BINARY_OP_LSHIFT,
  GCC_JIT_BINARY_OP_RSHIFT
};

gcc_jit_rvalue *
gcc_jit_context_new_binary_op (gcc_jit_context *ctxt,
       gcc_jit_location *loc,
       enum gcc_jit_binary_op op,
       gcc_jit_type *result_type,
       gcc_jit_rvalue *a, gcc_jit_rvalue *b);


enum gcc_jit_unary_op
{
  GCC_JIT_UNARY_OP_MINUS,
  GCC_JIT_UNARY_OP_BITWISE_NEGATE,
  GCC_JIT_UNARY_OP_LOGICAL_NEGATE,
  GCC_JIT_UNARY_OP_ABS
};


gcc_jit_rvalue *
gcc_jit_context_new_unary_op (gcc_jit_context *ctxt,
    gcc_jit_location *loc,
    enum gcc_jit_unary_op op,
    gcc_jit_type *result_type,
    gcc_jit_rvalue *rvalue);

gcc_jit_rvalue *
gcc_jit_param_as_rvalue (gcc_jit_param *param);

void
gcc_jit_block_end_with_return (gcc_jit_block *block,
       gcc_jit_location *loc,
       gcc_jit_rvalue *rvalue);


typedef ... gcc_jit_result;

gcc_jit_result *
gcc_jit_context_compile (gcc_jit_context *ctxt);

void
gcc_jit_context_release (gcc_jit_context *ctxt);

void *
gcc_jit_result_get_code (gcc_jit_result *result,
    const char *funcname);

void
gcc_jit_result_release (gcc_jit_result *result);

gcc_jit_rvalue *
gcc_jit_context_new_string_literal (gcc_jit_context *ctxt,
    const char *value);

void
gcc_jit_block_add_eval (gcc_jit_block *block,
    gcc_jit_location *loc,
    gcc_jit_rvalue *rvalue);

gcc_jit_rvalue *
gcc_jit_context_new_call (gcc_jit_context *ctxt,
  gcc_jit_location *loc,
  gcc_jit_function *func,
  int numargs , gcc_jit_rvalue **args);


extern gcc_jit_rvalue *
gcc_jit_context_new_rvalue_from_int (gcc_jit_context *ctxt,
     gcc_jit_type *numeric_type,
     int value);


enum gcc_jit_comparison
{
  GCC_JIT_COMPARISON_EQ,
  GCC_JIT_COMPARISON_NE,
  GCC_JIT_COMPARISON_LT,
  GCC_JIT_COMPARISON_LE,
  GCC_JIT_COMPARISON_GT,
  GCC_JIT_COMPARISON_GE
};

gcc_jit_rvalue *
gcc_jit_context_new_comparison (gcc_jit_context *ctxt,
    gcc_jit_location *loc,
    enum gcc_jit_comparison op,
    gcc_jit_rvalue *a, gcc_jit_rvalue *b);

void
gcc_jit_block_end_with_conditional(gcc_jit_block *block,
    gcc_jit_location *loc,
    gcc_jit_rvalue *boolval,
    gcc_jit_block *on_true,
    gcc_jit_block *on_false);

typedef ... gcc_jit_lvalue;

gcc_jit_lvalue *
gcc_jit_function_new_local (gcc_jit_function *func,
    gcc_jit_location *loc,
    gcc_jit_type *type,
    const char *name);

void
gcc_jit_block_add_assignment (gcc_jit_block *block,
    gcc_jit_location *loc,
    gcc_jit_lvalue *lvalue,
    gcc_jit_rvalue *rvalue);

gcc_jit_rvalue *
gcc_jit_lvalue_as_rvalue (gcc_jit_lvalue *lvalue);
""")

lib = ffi.dlopen('libgccjit.so.0')


class Type(enum.Enum):
    CONST_CHAR_PTR = lib.GCC_JIT_TYPE_CONST_CHAR_PTR
    INT = lib.GCC_JIT_TYPE_INT


string_to_enumtype = {
    'const char*': Type.CONST_CHAR_PTR,
    'int': Type.INT
}


def enumtype(value):
    if isinstance(value, Type):
        return value
    elif isinstance(value, str):
        return string_to_enumtype[value]

    assert(0)


class Function(enum.Enum):
    IMPORTED = lib.GCC_JIT_FUNCTION_IMPORTED
    EXPORTED = lib.GCC_JIT_FUNCTION_EXPORTED


class BinaryOp(enum.Enum):
    PLUS = lib.GCC_JIT_BINARY_OP_PLUS
    MULT = lib.GCC_JIT_BINARY_OP_MULT


def asrvalue(value):
    typname = ffi.typeof(value).cname
    if typname == 'gcc_jit_rvalue *':
        return value
    elif typname == 'gcc_jit_param *':
        return lib.gcc_jit_param_as_rvalue(value)
    elif typname == 'gcc_jit_lvalue *':
        return lib.gcc_jit_lvalue_as_rvalue(value)

    assert(0)


string_to_binop = {
    '+': BinaryOp.PLUS,
    '*': BinaryOp.MULT
}

def binop(value):
    if isinstance(value, BinaryOp):
        return value
    elif isinstance(value, str):
        return string_to_binop[value]

    assert(0)


class UnaryOp(enum.Enum):
    MINUS = lib.GCC_JIT_UNARY_OP_MINUS
    BITWISE_NEGATE = lib.GCC_JIT_UNARY_OP_BITWISE_NEGATE
    LOGICAL_NEGATE = lib.GCC_JIT_UNARY_OP_LOGICAL_NEGATE
    ABS = lib.GCC_JIT_UNARY_OP_ABS


string_to_unaryop = {
    '-': UnaryOp.MINUS,
    '~': UnaryOp.BITWISE_NEGATE,
    '!': UnaryOp.LOGICAL_NEGATE,
    'abs': UnaryOp.ABS
}


def unaryop(value):
    if isinstance(value, UnaryOp):
        return value
    elif isinstance(value, str):
        return string_to_unaryop[value]

    assert(0)


class ComparisonOp(enum.Enum):
    EQ = lib.GCC_JIT_COMPARISON_EQ
    NE = lib.GCC_JIT_COMPARISON_NE
    LT = lib.GCC_JIT_COMPARISON_LT
    LE = lib.GCC_JIT_COMPARISON_LE
    GT = lib.GCC_JIT_COMPARISON_GT
    GE = lib.GCC_JIT_COMPARISON_GE


string_to_compop = {
    '==': ComparisonOp.EQ,
    '!=': ComparisonOp.NE,
    '<': ComparisonOp.LT,
    '<=': ComparisonOp.LE,
    '>': ComparisonOp.GT,
    '>=': ComparisonOp.GE
}


def compop(value):
    if isinstance(value, ComparisonOp):
        return value
    elif isinstance(value, str):
        return string_to_compop[value]

    assert(0)


class Context:
    def __init__(self, *, optimization_level=None, dump=False):
        self.ctxt = lib.gcc_jit_context_acquire()
        if optimization_level:
            lib.gcc_jit_context_set_int_option(
                self.ctxt, lib.GCC_JIT_INT_OPTION_OPTIMIZATION_LEVEL,
                optimization_level)
        if dump:
            lib.gcc_jit_context_set_bool_option(
                self.ctxt, lib.GCC_JIT_BOOL_OPTION_DUMP_GENERATED_CODE, 1)

        self._type_cache = {}

    def type(self, typ):
        if repr(typ).startswith('<cdata '):
            return typ

        typ = enumtype(typ)

        if typ not in self._type_cache:
            self._type_cache[typ] = lib.gcc_jit_context_get_type(
                self.ctxt, typ.value)

        return self._type_cache[typ]

    def param(self, typ, name):
        typ = self.type(typ)

        return lib.gcc_jit_context_new_param(
            self.ctxt, ffi.NULL, typ, name.encode())

    def function(self, fun_type, ret_type, name, params=None):
        ret_type = self.type(ret_type)
        variadic = 0
        if params:
            if params[-1] == ...:
                variadic = 1
                params.pop()
            params = ffi.new("gcc_jit_param*[]", params)

        params = params or ffi.NULL
        len_params = len(params) if params else 0
        return lib.gcc_jit_context_new_function(
            self.ctxt, ffi.NULL, fun_type.value, ret_type, name.encode(),
            len_params, params, variadic)

    def local(self, function, typ, name):
        typ = self.type(typ)

        return lib.gcc_jit_function_new_local(
            function, ffi.NULL, typ, name.encode())

    def imported_function(self, ret_type, name, params=None):
        return self.function(
            Function.IMPORTED, ret_type, name, params)

    def exported_function(self, ret_type, name, params=None):
        return self.function(
            Function.EXPORTED, ret_type, name, params)

    def integer(self, value):
        typ = self.type("int")
        return lib.gcc_jit_context_new_rvalue_from_int(self.ctxt, typ, value)

    def string_literal(self, value):
        return lib.gcc_jit_context_new_string_literal(self.ctxt, value)

    def call(self, function, arguments=None):
        if arguments:
            arguments = ffi.new("gcc_jit_rvalue*[]", arguments)
        return lib.gcc_jit_context_new_call(
            self.ctxt, ffi.NULL, function, len(arguments), arguments)

    def block(self, function):
        blck = lib.gcc_jit_function_new_block(function, ffi.NULL)

        return Block(blck)

    def binary(self, operation, res_type, left, right):
        res_type = self.type(res_type)
        operation = binop(operation)
        left, right = asrvalue(left), asrvalue(right)
        return lib.gcc_jit_context_new_binary_op(
            self.ctxt, ffi.NULL, operation.value, res_type, left, right)

    def unary(self, operation, res_type, value):
        res_type = self.type(res_type)
        operation = unaryop(operation)
        value = asrvalue(value)
        return lib.gcc_jit_context_new_unary_op(
            self.ctxt, ffi.NULL, operation.value, res_type, value)

    def comparison(self, operation, left, right):
        operation = compop(operation)
        left, right = asrvalue(left), asrvalue(right)
        return lib.gcc_jit_context_new_comparison(
            self.ctxt, ffi.NULL, operation.value, left, right)

    def compile(self):
        rslt = lib.gcc_jit_context_compile(self.ctxt)

        return Result(rslt)

    def close(self):
        lib.gcc_jit_context_release(self.ctxt)


class Block:
    def __init__(self, blck):
        self.blck = blck

    def add_eval(self, lvalue):
        lib.gcc_jit_block_add_eval(self.blck, ffi.NULL, lvalue)

    def add_assignment(self, lvalue, rvalue):
        lib.gcc_jit_block_add_assignment(self.blck, ffi.NULL, lvalue, rvalue)

    def end_with_return(self, rvalue):
        rvalue = asrvalue(rvalue)
        lib.gcc_jit_block_end_with_return(self.blck, ffi.NULL, rvalue)

    def end_with_conditonal(self, rvalue, on_true, on_false):
        lib.gcc_jit_block_end_with_conditional(
            self.blck, ffi.NULL, rvalue, on_true.blck, on_false.blck)


class Result:
    def __init__(self, rslt):
        self.rslt = rslt

    def code(self, name):
        fn_ptr = lib.gcc_jit_result_get_code(self.rslt, name.encode())
        assert fn_ptr != ffi.NULL

        return fn_ptr

    def close(self):
        lib.gcc_jit_result_release(self.rslt)
