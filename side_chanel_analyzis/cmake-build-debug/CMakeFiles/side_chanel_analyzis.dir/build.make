# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/user/data/clion-2018.3.4/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/user/data/clion-2018.3.4/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/side_chanel_analyzis.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/side_chanel_analyzis.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/side_chanel_analyzis.dir/flags.make

CMakeFiles/side_chanel_analyzis.dir/src/main.c.o: CMakeFiles/side_chanel_analyzis.dir/flags.make
CMakeFiles/side_chanel_analyzis.dir/src/main.c.o: ../src/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/side_chanel_analyzis.dir/src/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/side_chanel_analyzis.dir/src/main.c.o   -c /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/main.c

CMakeFiles/side_chanel_analyzis.dir/src/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/side_chanel_analyzis.dir/src/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/main.c > CMakeFiles/side_chanel_analyzis.dir/src/main.c.i

CMakeFiles/side_chanel_analyzis.dir/src/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/side_chanel_analyzis.dir/src/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/main.c -o CMakeFiles/side_chanel_analyzis.dir/src/main.c.s

CMakeFiles/side_chanel_analyzis.dir/src/common.c.o: CMakeFiles/side_chanel_analyzis.dir/flags.make
CMakeFiles/side_chanel_analyzis.dir/src/common.c.o: ../src/common.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/side_chanel_analyzis.dir/src/common.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/side_chanel_analyzis.dir/src/common.c.o   -c /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/common.c

CMakeFiles/side_chanel_analyzis.dir/src/common.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/side_chanel_analyzis.dir/src/common.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/common.c > CMakeFiles/side_chanel_analyzis.dir/src/common.c.i

CMakeFiles/side_chanel_analyzis.dir/src/common.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/side_chanel_analyzis.dir/src/common.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/common.c -o CMakeFiles/side_chanel_analyzis.dir/src/common.c.s

CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.o: CMakeFiles/side_chanel_analyzis.dir/flags.make
CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.o: ../src/ecc_analyze.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.o   -c /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/ecc_analyze.c

CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/ecc_analyze.c > CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.i

CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/src/ecc_analyze.c -o CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.s

# Object files for target side_chanel_analyzis
side_chanel_analyzis_OBJECTS = \
"CMakeFiles/side_chanel_analyzis.dir/src/main.c.o" \
"CMakeFiles/side_chanel_analyzis.dir/src/common.c.o" \
"CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.o"

# External object files for target side_chanel_analyzis
side_chanel_analyzis_EXTERNAL_OBJECTS =

side_chanel_analyzis: CMakeFiles/side_chanel_analyzis.dir/src/main.c.o
side_chanel_analyzis: CMakeFiles/side_chanel_analyzis.dir/src/common.c.o
side_chanel_analyzis: CMakeFiles/side_chanel_analyzis.dir/src/ecc_analyze.c.o
side_chanel_analyzis: CMakeFiles/side_chanel_analyzis.dir/build.make
side_chanel_analyzis: CMakeFiles/side_chanel_analyzis.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable side_chanel_analyzis"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/side_chanel_analyzis.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/side_chanel_analyzis.dir/build: side_chanel_analyzis

.PHONY : CMakeFiles/side_chanel_analyzis.dir/build

CMakeFiles/side_chanel_analyzis.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/side_chanel_analyzis.dir/cmake_clean.cmake
.PHONY : CMakeFiles/side_chanel_analyzis.dir/clean

CMakeFiles/side_chanel_analyzis.dir/depend:
	cd /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug /home/user/data/SKOLA/PV204/project/GnuTLS-work/side_chanel_analyzis/cmake-build-debug/CMakeFiles/side_chanel_analyzis.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/side_chanel_analyzis.dir/depend
