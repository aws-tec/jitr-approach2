afr_module()

afr_set_lib_metadata(ID "keygen")
afr_set_lib_metadata(DESCRIPTION "This library helps to generate device private key and certificate.")
afr_set_lib_metadata(DISPLAY_NAME "Device Key and Certificate Generator")
afr_set_lib_metadata(CATEGORY "Amazon Services")
afr_set_lib_metadata(VERSION "1.0.0")
afr_set_lib_metadata(IS_VISIBLE "true")

set(src_dir "${CMAKE_CURRENT_LIST_DIR}/src")
set(inc_dir "${CMAKE_CURRENT_LIST_DIR}/include")

afr_module_sources(
    ${AFR_CURRENT_MODULE}
    PUBLIC
        "${src_dir}/aws_iot_key_gen.c"
        "${inc_dir}/aws_iot_key_gen.h"
)

afr_module_include_dirs(
    ${AFR_CURRENT_MODULE}
    PUBLIC
        "${inc_dir}"
)

afr_module_dependencies(
    ${AFR_CURRENT_MODULE}
    PUBLIC
        3rdparty::mbedtls
)
