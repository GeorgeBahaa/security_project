# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = C:\softwares\cmake-3.28.0-windows-x86_64\bin\cmake.exe

# The command to remove a file.
RM = C:\softwares\cmake-3.28.0-windows-x86_64\bin\cmake.exe -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "G:\Semester 9\New folder\security_project"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "G:\Semester 9\New folder\security_project\build"

# Include any dependencies generated for this target.
include CMakeFiles/project.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/project.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/project.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/project.dir/flags.make

CMakeFiles/project.dir/main.cpp.obj: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/main.cpp.obj: CMakeFiles/project.dir/includes_CXX.rsp
CMakeFiles/project.dir/main.cpp.obj: G:/Semester\ 9/New\ folder/security_project/main.cpp
CMakeFiles/project.dir/main.cpp.obj: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="G:\Semester 9\New folder\security_project\build\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/project.dir/main.cpp.obj"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/project.dir/main.cpp.obj -MF CMakeFiles\project.dir\main.cpp.obj.d -o CMakeFiles\project.dir\main.cpp.obj -c "G:\Semester 9\New folder\security_project\main.cpp"

CMakeFiles/project.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/project.dir/main.cpp.i"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "G:\Semester 9\New folder\security_project\main.cpp" > CMakeFiles\project.dir\main.cpp.i

CMakeFiles/project.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/project.dir/main.cpp.s"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "G:\Semester 9\New folder\security_project\main.cpp" -o CMakeFiles\project.dir\main.cpp.s

CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj: CMakeFiles/project.dir/includes_CXX.rsp
CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj: G:/Semester\ 9/New\ folder/security_project/rsa_encryption_decryption/openssl_rsa.cpp
CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="G:\Semester 9\New folder\security_project\build\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj -MF CMakeFiles\project.dir\rsa_encryption_decryption\openssl_rsa.cpp.obj.d -o CMakeFiles\project.dir\rsa_encryption_decryption\openssl_rsa.cpp.obj -c "G:\Semester 9\New folder\security_project\rsa_encryption_decryption\openssl_rsa.cpp"

CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.i"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "G:\Semester 9\New folder\security_project\rsa_encryption_decryption\openssl_rsa.cpp" > CMakeFiles\project.dir\rsa_encryption_decryption\openssl_rsa.cpp.i

CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.s"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "G:\Semester 9\New folder\security_project\rsa_encryption_decryption\openssl_rsa.cpp" -o CMakeFiles\project.dir\rsa_encryption_decryption\openssl_rsa.cpp.s

CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj: CMakeFiles/project.dir/includes_CXX.rsp
CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj: G:/Semester\ 9/New\ folder/security_project/rsa_authentication/rsa_auth.cpp
CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="G:\Semester 9\New folder\security_project\build\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj -MF CMakeFiles\project.dir\rsa_authentication\rsa_auth.cpp.obj.d -o CMakeFiles\project.dir\rsa_authentication\rsa_auth.cpp.obj -c "G:\Semester 9\New folder\security_project\rsa_authentication\rsa_auth.cpp"

CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.i"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "G:\Semester 9\New folder\security_project\rsa_authentication\rsa_auth.cpp" > CMakeFiles\project.dir\rsa_authentication\rsa_auth.cpp.i

CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.s"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "G:\Semester 9\New folder\security_project\rsa_authentication\rsa_auth.cpp" -o CMakeFiles\project.dir\rsa_authentication\rsa_auth.cpp.s

CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj: CMakeFiles/project.dir/includes_CXX.rsp
CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj: G:/Semester\ 9/New\ folder/security_project/aes_enc_dec/aes.cpp
CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="G:\Semester 9\New folder\security_project\build\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj -MF CMakeFiles\project.dir\aes_enc_dec\aes.cpp.obj.d -o CMakeFiles\project.dir\aes_enc_dec\aes.cpp.obj -c "G:\Semester 9\New folder\security_project\aes_enc_dec\aes.cpp"

CMakeFiles/project.dir/aes_enc_dec/aes.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/project.dir/aes_enc_dec/aes.cpp.i"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "G:\Semester 9\New folder\security_project\aes_enc_dec\aes.cpp" > CMakeFiles\project.dir\aes_enc_dec\aes.cpp.i

CMakeFiles/project.dir/aes_enc_dec/aes.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/project.dir/aes_enc_dec/aes.cpp.s"
	C:\MinGW64\bin\c++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "G:\Semester 9\New folder\security_project\aes_enc_dec\aes.cpp" -o CMakeFiles\project.dir\aes_enc_dec\aes.cpp.s

# Object files for target project
project_OBJECTS = \
"CMakeFiles/project.dir/main.cpp.obj" \
"CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj" \
"CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj" \
"CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj"

# External object files for target project
project_EXTERNAL_OBJECTS =

project.exe: CMakeFiles/project.dir/main.cpp.obj
project.exe: CMakeFiles/project.dir/rsa_encryption_decryption/openssl_rsa.cpp.obj
project.exe: CMakeFiles/project.dir/rsa_authentication/rsa_auth.cpp.obj
project.exe: CMakeFiles/project.dir/aes_enc_dec/aes.cpp.obj
project.exe: CMakeFiles/project.dir/build.make
project.exe: CMakeFiles/project.dir/linkLibs.rsp
project.exe: CMakeFiles/project.dir/objects1.rsp
project.exe: CMakeFiles/project.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir="G:\Semester 9\New folder\security_project\build\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX executable project.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\project.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/project.dir/build: project.exe
.PHONY : CMakeFiles/project.dir/build

CMakeFiles/project.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\project.dir\cmake_clean.cmake
.PHONY : CMakeFiles/project.dir/clean

CMakeFiles/project.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" "G:\Semester 9\New folder\security_project" "G:\Semester 9\New folder\security_project" "G:\Semester 9\New folder\security_project\build" "G:\Semester 9\New folder\security_project\build" "G:\Semester 9\New folder\security_project\build\CMakeFiles\project.dir\DependInfo.cmake" "--color=$(COLOR)"
.PHONY : CMakeFiles/project.dir/depend
