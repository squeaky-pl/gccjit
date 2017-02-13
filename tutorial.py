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

    char_ptr = context.pointer_type("char")
    param_buffer = context.param(char_ptr, "buffer")

    fill = context.exported_function(
        "int", "fill", [param_buffer])

    block = context.block(fill)

    a0 = context.array_access(param_buffer, context.integer(0))
    block.add_assignment(a0, context.integer(0xff, "char"))
    a1 = context.array_access(param_buffer, context.integer(1))
    block.add_assignment(a1, context.integer(0xff, "char"))

    block.end_with_return(context.integer(0))

    result = context.compile()
    context.close()

    fn_ptr = result.code("square")

    square = ffi.cast("int (*)(int, int)", fn_ptr)
    x = square(5, 1)
    print(x)

    buffer = ffi.new("char[2]", b"\0\0")
    fn_ptr = result.code("fill")
    fill = ffi.cast("int (*)(char*)", fn_ptr)
    x = fill(buffer)
    print(x)
    print(ffi.unpack(buffer, 2))

    result.close()


main()
