# libavproto - avim av层协议的实现

---

使用办法, 需要将 libavim 和 avim_proto_doc 两个仓库同时作为 submodule 添加进来.

然后使用

	add_subdirectory(avim_proto_doc)
	add_subdirectory(libavim)

然后用

	add_executable(yourtarget xxx.cpp)
	target_link_libraries(yourtarget avim++)

就可以使用了.

如果使用 C 接口, 则使用

	target_link_libraries(yourtarget avproto)
