from gccjit import lib, ffi, Context, Type, Function, BinaryOp


def main():
    context = Context(optimization_level=3, dump=True)

    param_i = context.param("int", "i")
    param_z = context.param("int", "z")

#    param_format = context.param("const char*", "format")
#    printf_func = context.imported_function(
#        "int", "printf", [param_format, ...])

    func = context.exported_function(
        "int", "square", [param_i, param_z])

    block = context.block(func)

#    hello = context.string_literal(b"hello\n")
#    printf_call = context.call(printf_func, [hello])

#    block.add_eval(printf_call)

    multiplication = context.binary('*', "int", param_i, param_i)

    addition = context.binary('+', "int", multiplication, param_z)

    inc = context.binary('+', "int", addition, context.integer(1))

    minus = context.unary('-', 'int', inc)

    block.end_with_return(minus)

    result = context.compile()
    context.close()

    fn_ptr = result.code("square")

    square = ffi.cast("int (*)(int, int)", fn_ptr)
    x = square(5, 1)
    print(x)

    result.close()


main()
