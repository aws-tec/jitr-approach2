# C SDK MQTT demo
afr_demo_module(jitr)

afr_module_sources(
    ${AFR_CURRENT_MODULE}
    INTERFACE
        "${CMAKE_CURRENT_LIST_DIR}/jitr.c"
)
afr_module_dependencies(
    ${AFR_CURRENT_MODULE}
    INTERFACE
		AFR::mqtt
)



