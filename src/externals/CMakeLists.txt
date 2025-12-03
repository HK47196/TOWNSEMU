add_subdirectory(connect_fssimplewindow)
add_subdirectory(fssimplewindow/src)
add_subdirectory(yssimplesound/src)
add_subdirectory(d77)
add_subdirectory(yspng)
add_subdirectory(yssocket/src)

include(FetchContent)
FetchContent_Declare(
  replxx
  GIT_REPOSITORY https://github.com/AmokHuginnsson/replxx.git
  GIT_TAG        release-0.0.4
)
FetchContent_MakeAvailable(replxx)
