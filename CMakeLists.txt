


# 本CMakeLists.txt的project名称
# 会自动创建两个变量，PROJECT_SOURCE_DIR和PROJECT_NAME
# ${PROJECT_SOURCE_DIR}：本CMakeLists.txt所在的文件夹路径
# ${PROJECT_NAME}：本CMakeLists.txt的project名称
project(DumpElf)

include_directories("/usr/lib/gcc/x86_64-linux-gnu/9/include/")
add_definitions("-Wall -g")

aux_source_directory(${CMAKE_SOURCE_DIR} SRC)
add_executable(main ${SRC})
