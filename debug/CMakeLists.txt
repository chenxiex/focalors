add_executable(debug debug.cpp)
target_compile_options(debug PRIVATE -Wall -Wextra -g)
target_link_libraries(debug focalors)