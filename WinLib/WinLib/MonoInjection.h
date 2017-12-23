#pragma once
#include <Windows.h>
#include <string>

namespace WinLib {
	namespace PE {
		namespace Loader {
			namespace Mono {
				class MonoInjection {
				private:
					/* Mono-API */
					void* (*mono_domain_get)();
					void* (*mono_assembly_open)(const char* exeName, void* status);
					void* (*mono_assembly_get_image)(void* assembly);
					void* (*mono_class_from_name)(void *image, const char* name_space, const char *name);
					void* (*mono_class_get_method_from_name)(void* klass, const char* methodname, int arguments);
					void* (*mono_runtime_invoke)(void* method, void* obj, void **args, void** exc);
					void* (*mono_get_root_domain)();
					void* (*mono_thread_attach)(void* root);
					void* (*mono_domain_assembly_open)(void* domain, const char* path);

					static MonoInjection* _instance;
					MonoInjection();
				public:
					static MonoInjection* getInstance();

					bool inject(const std::string& path, const std::string& entry_namespace, const std::string& entry_class, const std::string& entry_method);
				};
			}
		}
	}
}