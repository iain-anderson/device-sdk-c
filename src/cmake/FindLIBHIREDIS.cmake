find_path (LIBHIREDIS_INCLUDE_DIR hiredis/hiredis.h)
find_library (LIBHIREDIS_LIBRARIES NAMES hiredis libhiredis)
include (FindPackageHandleStandardArgs)
find_package_handle_standard_args (LIBHIREDIS DEFAULT_MSG LIBHIREDIS_LIBRARIES LIBHIREDIS_INCLUDE_DIR)
