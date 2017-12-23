#include "MonoInjection.h"

using WinLib::PE::Loader::Mono::MonoInjection;

MonoInjection* MonoInjection::_instance = nullptr;

MonoInjection* MonoInjection::getInstance() {
	if (_instance == nullptr) {
		_instance = new MonoInjection();
	}

	return _instance;
}

MonoInjection::MonoInjection() {
	auto handle = GetModuleHandle("mono.dll");
	
	*(FARPROC *)&this->mono_domain_get					= GetProcAddress(handle, "mono_domain_open");
	*(FARPROC *)&this->mono_assembly_open				= GetProcAddress(handle, "mono_assembly_open");
	*(FARPROC *)&this->mono_assembly_get_image			= GetProcAddress(handle, "mono_assembly_get_image");
	*(FARPROC *)&this->mono_class_from_name				= GetProcAddress(handle, "mono_class_from_name");
	*(FARPROC *)&this->mono_class_get_method_from_name	= GetProcAddress(handle, "mono_class_get_method_from_name");
	*(FARPROC *)&this->mono_runtime_invoke				= GetProcAddress(handle, "mono_runtime_invoke");
	*(FARPROC *)&this->mono_get_root_domain				= GetProcAddress(handle, "mono_get_root_domain");
	*(FARPROC *)&this->mono_thread_attach				= GetProcAddress(handle, "mono_thread_attach");
	*(FARPROC *)&this->mono_domain_assembly_open		= GetProcAddress(handle, "mono_domain_assembly_open");
}

bool MonoInjection::inject(const std::string& path, const std::string& entry_namespace, const std::string& entry_class, const std::string& entry_method) {
	auto root_domain = this->mono_get_root_domain();
	auto thread = this->mono_thread_attach(root_domain);
	auto domain = this->mono_domain_get();

	if (!domain)
		return false;

	auto assembly = this->mono_domain_assembly_open(domain, path.c_str());

	if (!assembly)
		return false;

	auto image = mono_assembly_get_image(assembly);

	if (!image)
		return false;

	auto mono_class = this->mono_class_from_name(image, entry_namespace.c_str(), entry_class.c_str());

	if (!mono_class)
		return false;

	auto method = this->mono_class_get_method_from_name(mono_class, entry_method.c_str(), 0);

	if (!method)
		return false;

	//Invoke EntryPoint
	auto obj = this->mono_runtime_invoke(method, nullptr, nullptr, nullptr);

	return true;
}