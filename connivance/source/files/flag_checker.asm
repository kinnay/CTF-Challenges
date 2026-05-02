
main:
	decrypt_program 2

	new_buffer
	append_buffer "romfs:/d"
	append_buffer "ragonfly"
	append_buffer ".bin\0\0\0\0"
	load_whole_file
	pop_var 0

	push_input
	invert_buffer

	push_buffer_size
	pop_var 2
	push_value 29
	pop_var 3
	compare 2 3
	jump_if_ne failure

	sha256
	pop_var 1

	rshift_bytes
	sha256
	push_var 1
	concat
	pop_var 1

	rshift_bytes
	sha256
	push_var 1
	concat
	pop_var 1

	rshift_bytes
	sha256
	push_var 1
	concat
	pop_var 1

	rshift_bytes
	sha256
	push_var 1
	concat
	pop_var 1

	rshift_bytes
	sha256
	push_var 1
	concat
	pop_var 1

	rshift_bytes
	sha256
	push_var 1
	concat
	pop_var 1

	rshift_bytes
	sha256
	push_var 1
	concat
	pop_var 1

	compare 0 1
	jump_if_eq success

failure:
	new_buffer
	append_buffer "Incorrec"
	append_buffer "t!\0\0\0\0\0\0"
	write_output
	jump end

success:
	new_buffer
	append_buffer "Correct!"
	write_output

end:
