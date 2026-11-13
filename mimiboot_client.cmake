# MimiBoot client library for pico-sdk apps:
#
#   include(path/to/mimiboot/mimiboot_client.cmake)
#   target_link_libraries(my_app mimiboot_client)
#
# Then in the app: mb_client_init(&mb_rp2350_port); ... mb_client_confirm();

if(NOT TARGET mimiboot_client)
    set(_MB ${CMAKE_CURRENT_LIST_DIR})
    add_library(mimiboot_client INTERFACE)
    target_sources(mimiboot_client INTERFACE
        ${_MB}/core/mb_hash.c
        ${_MB}/core/mb_ed25519.c
        ${_MB}/core/mb_image.c
        ${_MB}/core/mb_bcl.c
        ${_MB}/core/mb_control.c
        ${_MB}/core/mb_grub.c
        ${_MB}/core/mb_config.c
        ${_MB}/core/mb_recv.c
        ${_MB}/client/mb_client.c
    )
    target_include_directories(mimiboot_client INTERFACE ${_MB} ${_MB}/include)
    if(PICO_PLATFORM STREQUAL "rp2040")
        target_sources(mimiboot_client INTERFACE ${_MB}/port/rp2040/mb_rp2040.c)
        target_compile_definitions(mimiboot_client INTERFACE MB_RP2040_CLIENT=1)
        target_link_libraries(mimiboot_client INTERFACE pico_stdlib pico_stdio_usb hardware_watchdog hardware_irq)
    else()
        target_sources(mimiboot_client INTERFACE ${_MB}/port/rp2350/mb_rp2350.c)
        target_compile_definitions(mimiboot_client INTERFACE MB_RP2350_CLIENT=1)
        target_link_libraries(mimiboot_client INTERFACE pico_sha256)
    endif()
    target_link_libraries(mimiboot_client INTERFACE pico_bootrom pico_flash hardware_flash)
    # Flash writes go through flash_safe_execute, which refuses
    # (PICO_ERROR_NOT_PERMITTED) unless it knows core1 can't be running from
    # flash. Apps that never start core1: explicitly turn this ON. Apps that do: turn it
    # OFF and call flash_safe_execute_core_init() on core1.
    option(MIMIBOOT_CLIENT_SINGLE_CORE "the app never runs code on core1" OFF)
    if(MIMIBOOT_CLIENT_SINGLE_CORE)
        target_compile_definitions(mimiboot_client INTERFACE PICO_FLASH_ASSUME_CORE1_SAFE=1)
    endif()
endif()

if(DEFINED MIMIBOOT_KEYS)
 get_filename_component(_mb_keys ${MIMIBOOT_KEYS} ABSOLUTE)
 target_compile_definitions(mimiboot_client INTERFACE MB_KEYS_HEADER="${_mb_keys}")
endif()
if(MIMIBOOT_REQUIRE_SIGNATURE)
 if(NOT DEFINED MIMIBOOT_KEYS)
  message(FATAL_ERROR "Client signature policy requires MIMIBOOT_KEYS")
 endif()
 target_compile_definitions(mimiboot_client INTERFACE MB_REQUIRE_SIGNATURE=1)
endif()
