#include "Console.h"

namespace Output {
	void Console::printLogType(LogType type) {
		if (type == LogType::ERR) {
			Console::setColor(COLOR_RED);
			std::cout << "ERROR ";
		}
		else if (type == LogType::DEBUG) {
			Console::setColor(COLOR_GREEN);
			std::cout << "DEBUG ";
		}
		else if (type == LogType::INFO) {
			Console::setColor(COLOR_LIGHTWHITE);
			std::cout << "INFO  ";
		}
		else if (type == LogType::WARN) {
			Console::setColor(COLOR_LIGHTYELLOW);
			std::cout << "WARN  ";
		}
	}

	void Console::setColor(int color) {
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdout == INVALID_HANDLE_VALUE)
		{
			std::cout << "Error while getting input handle" << std::endl;
			return;
		}

		SetConsoleTextAttribute(hStdout, color);
	}

	std::string Console::getCurrentTime()
	{
		time_t rawtime = time(0);
		struct tm  timeinfo;
		localtime_s(&timeinfo, &rawtime);

		auto now = std::chrono::system_clock::now();
		auto now_c = std::chrono::system_clock::to_time_t(now);

		std::stringstream ss;
		ss << std::put_time(&timeinfo, "[%H:%M:%S]");

		return ss.str();
	}

	bool Console::spawnInstance() {
		if (!AllocConsole())
			return false;

		FILE* file;
		freopen_s(&file, "CONOUT$", "w", stdout);

		return true;
	}

	void Console::setTitle(std::string title) {
		SetConsoleTitle(title.c_str());
	}
}