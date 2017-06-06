#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <string>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <chrono>
#include <sstream>

namespace Output {

	enum LogType {
		ERR,
		WARN,
		DEBUG,
		INFO
	};

	class Console {
	private:
		static void setColor(int color);
		static std::string getCurrentTime();
		static void printLogType(LogType type);
	public:
		static constexpr const __int32 COLOR_BLACK = 0x0;
		static constexpr const __int32 COLOR_GRAY = 0x8;
		static constexpr const __int32 COLOR_YELLOW = 0x6;
		static constexpr const __int32 COLOR_LIGHTYELLOW = 0xE;
		static constexpr const __int32 COLOR_BLUE = 0x1;
		static constexpr const __int32 COLOR_LIGHTBLUE = 0x9;
		static constexpr const __int32 COLOR_GREEN = 0x2;
		static constexpr const __int32 COLOR_LIGHTGREEN = 0xA;
		static constexpr const __int32 COLOR_RED = 0x4;
		static constexpr const __int32 COLOR_LIGHTRED = 0xC;
		static constexpr const __int32 COLOR_WHITE = 0x7;
		static constexpr const __int32 COLOR_LIGHTWHITE = 0xF;


		static bool spawnInstance();
		static void setTitle(std::string title);

		template <typename T>
		static void print(T value)
		{
			std::cout << value;
		}

		template <typename T>
		static void printLine(T value)
		{
			std::cout << value << std::endl;
		}

		template <typename T>
		static void printLog(LogType type, T value)
		{
			Console::printLogType(type);
			Console::setColor(COLOR_WHITE);
			std::cout << getCurrentTime();
			Console::setColor(COLOR_GRAY);
			std::cout << " - ";
			Console::setColor(COLOR_LIGHTWHITE);
			std::cout << value << std::endl;
		}
	};
}