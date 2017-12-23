#pragma once
#include <Windows.h>
#include <iostream>
#include <functional>
#include <thread>

namespace WinLib {
	namespace Communication {
		namespace Raw {
			class RawMemoryCommunication {
			public:
				/* Data */
				enum STATE {
					WAIT = 0,
					NEW = 1
				};

				class InternalBuffer {
				public:
					STATE state;
					uint64_t* ptr;
				};

				typedef std::function<void(const InternalBuffer* state)> event_callback;
				event_callback callback;

				/* Logic */
				RawMemoryCommunication();
				~RawMemoryCommunication();

				bool init();
				bool setState(const STATE state);
				bool registerCallback(RawMemoryCommunication::event_callback callback);
				LPVOID getInternalAdress();

			private:
				/* Data */
				//LPVOID internalBuffer;
				InternalBuffer* internalBuffer;
				std::thread thread;

				/* Logic */
				void internal_thread();
			};
		}
	}
}