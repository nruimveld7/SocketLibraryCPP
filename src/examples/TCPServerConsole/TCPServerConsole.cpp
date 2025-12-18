#include <iostream>
#include <string>
#include <algorithm>
#include <limits>
#include <thread>
#include <mutex>
#include <future>

#define NOMINMAX
#define TCPSOCKET
#include "SocketLibrary.h"
#include <Windows.h>

using namespace SocketLibrary;

void OnRead(unsigned char* message, size_t byteCount, SOCKET sender);
void UpdateHandler(std::string message);
void ErrorHandler(std::string message, int wsaCode);
void PrintToConsole(const std::string& message);
void ManagerHandler();
bool CheckManager();
void InputHandler(std::string input);
bool PipeWrite(std::string data);
bool PipeRead(std::string& data);
bool PipeCheck();
std::string DecodeError(int errorCode);
bool ManagerRequest();
void Configure();
std::string GetConfig(const std::string& param);
std::string Trim(const std::string& str);
void Close();
std::string GetString(std::string prompt);
int GetInt(
  std::string prompt,
  int minVal = std::numeric_limits<int>::min(),
  int maxVal = std::numeric_limits<int>::max()
);

HANDLE g_pipeRead = INVALID_HANDLE_VALUE;
HANDLE g_pipeWrite = INVALID_HANDLE_VALUE;
bool g_spawned = false;
TCPServerSocket g_server;
std::mutex g_managerLock;
DWORD g_managerPid;

int main(int argc, char* argv[]) {
  if(argc == 4) {
    try {
      const uintptr_t readHandle = static_cast<uintptr_t>(std::stoull(argv[1]));
      const uintptr_t writeHandle = static_cast<uintptr_t>(std::stoull(argv[2]));
      g_pipeRead = reinterpret_cast<HANDLE>(readHandle);
      g_pipeWrite = reinterpret_cast<HANDLE>(writeHandle);
      g_managerPid = static_cast<DWORD>(std::stoul(argv[3]));
      g_spawned = (g_pipeRead && g_pipeRead != INVALID_HANDLE_VALUE && g_pipeWrite && g_pipeRead != INVALID_HANDLE_VALUE);
    } catch(...) {
      g_spawned = false;
    }
  }
  if(!g_spawned) {
    g_pipeRead = GetStdHandle(STD_INPUT_HANDLE);
    g_pipeWrite = GetStdHandle(STD_OUTPUT_HANDLE);
  }
  if(!g_pipeRead || g_pipeRead == INVALID_HANDLE_VALUE || !g_pipeWrite || g_pipeWrite == INVALID_HANDLE_VALUE) {
    std::cerr << "Invalid pipe/std handles.\n";
    return 1;
  }
  std::cout << "Read Pipe: " << g_pipeRead << std::endl;
  std::cout << "Write Pipe: " << g_pipeWrite << std::endl;
  PipeWrite("OK");
  Configure();
  if(!g_spawned) {
    std::cout << "Between messages, enter '/m' or '/c' to modify or close the socket respectively." << std::endl << std::endl;
  }
  std::cout << "Ready to communicate" << std::endl;
  std::cout << "Enter '/bc' to broadcast to all connected clients" << std::endl;
  std::cout << "Otherwise, begin typing the message to send" << std::endl;
  if(g_spawned) {
    std::thread monitor = std::thread(ManagerHandler);
    monitor.detach();
  }
  auto GetLine = [] {
    return std::async(std::launch::async, [] {
      std::string input;
      std::getline(std::cin, input);
      return input;
    });
  };
  std::future<std::string> line = GetLine();
  while(true) {
    if(!(line.valid() && line.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
      continue;
    }
    std::string input = line.get();
    line = GetLine();
    if(!(g_managerLock.try_lock())) {
      std::cout << "Waiting for server to finish..." << std::endl;
      std::lock_guard<std::mutex> lock(g_managerLock);
      InputHandler(input);
    } else {
      std::lock_guard<std::mutex> lock(g_managerLock, std::adopt_lock);
      InputHandler(input);
    }
  }
}

void OnRead(unsigned char* message, size_t byteCount, SOCKET sender) {
  if(message == nullptr) {
    PrintToConsole("Invalid message");
    return;
  }
  std::string str = "";
  for(int i = 0; i < byteCount; i++) {
    str += static_cast<char>(message[i]);
  }
  PrintToConsole(str);
}

void UpdateHandler(std::string message) {
  PrintToConsole(message);
}

void ErrorHandler(std::string message, int wsaCode) {
  PrintToConsole(message);
}

void PrintToConsole(const std::string& message) {
  std::cout << message << std::endl;
}

void ManagerHandler() {
  while(true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    if(!CheckManager()) {
      return;
    }
    bool closedByManager = false;
    if(PipeCheck()) {
      std::lock_guard<std::mutex> lock(g_managerLock);
      closedByManager = ManagerRequest();
    }
    if(closedByManager) {
      Close();
    }
  }
}

bool CheckManager() {
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_managerPid);
  if(hProcess == nullptr) {
    std::cerr << "Error opening process: " << DecodeError(GetLastError()) << std::endl;
    g_pipeRead = GetStdHandle(STD_INPUT_HANDLE);
    g_pipeWrite = GetStdHandle(STD_OUTPUT_HANDLE);
    g_spawned = false;
    return false;
  }
  DWORD exitCode;
  if(GetExitCodeProcess(hProcess, &exitCode)) {
    if(exitCode == STILL_ACTIVE) {
      CloseHandle(hProcess);
      return true;
    } else {
      CloseHandle(hProcess);
      g_pipeRead = GetStdHandle(STD_INPUT_HANDLE);
      g_pipeWrite = GetStdHandle(STD_OUTPUT_HANDLE);
      g_spawned = false;
      return false;
    }
  }
  CloseHandle(hProcess);
  g_pipeRead = GetStdHandle(STD_INPUT_HANDLE);
  g_pipeWrite = GetStdHandle(STD_OUTPUT_HANDLE);
  g_spawned = false;
  return false;
}

void InputHandler(std::string input) {
  if(input == "/m" && !g_spawned) {
    g_server.Close();
    Configure();
  } else if(input == "/c" && !g_spawned) {
    g_server.Close();
  } else if(input == "/bc") {
    std::string message = GetString("Enter the message to send: ");
    g_server.Broadcast(message.c_str(), static_cast<int>(message.size()));
  } else {
    std::cout << "Valid IPs:" << std::endl;
    const auto& clientAddresses = g_server.GetClientAddresses();
    if(clientAddresses.empty()) {
      std::cout << "No Connected Clients" << std::endl;
      return;
    }
    for(const auto& address : clientAddresses) {
      std::cout << address << std::endl;
    }
    std::string address = GetString("Enter the address of the connected client: ");
    g_server.Send(input.c_str(), static_cast<int>(input.size()), address);
  }
}

bool PipeWrite(std::string data) {
  if(!g_spawned) {
    data += "\n";
  } else {
    PrintToConsole("Sending " + data + " to the manager");
  }
  DWORD bytesWritten;
  BOOL success = WriteFile(g_pipeWrite, data.c_str(), static_cast<DWORD>(data.size()), &bytesWritten, NULL);
  if(!success || bytesWritten != data.size()) {
    std::cerr << "Failed to write to pipe! Error: " << DecodeError(GetLastError()) << std::endl;
    return false;
  }
  return true;
}

bool PipeRead(std::string& data) {
  if(!g_pipeRead || g_pipeRead == INVALID_HANDLE_VALUE) {
    std::cerr << "Invalid pipe read handle!" << std::endl;
    return false;
  }
  if(g_spawned) {
    DWORD available = 0;
    if(!PeekNamedPipe(g_pipeRead, nullptr, 0, nullptr, &available, nullptr) || available == 0) {
      return false;
    }
  }
  char buffer[256];
  DWORD bytesRead;
  if(!ReadFile(g_pipeRead, buffer, sizeof(buffer), &bytesRead, NULL) || bytesRead == 0) {
    std::cerr << "Failed to read from pipe! Error: " << DecodeError(GetLastError()) << std::endl;
    return false;
  }
  data.assign(buffer, bytesRead);
  if(g_spawned) {
    PrintToConsole("Received " + data + " from the manager");
  }
  return true;
}

bool PipeCheck() {
  DWORD bytesAvailable = 0;
  if(PeekNamedPipe(g_pipeRead, nullptr, 0, nullptr, &bytesAvailable, nullptr)) {
    return bytesAvailable > 0;
  }
  return false;
}

std::string DecodeError(int errorCode) {
  std::string result;
  LPSTR message = nullptr;

  // Call FormatMessageA to retrieve the error message
  DWORD chars = FormatMessageA(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK | FORMAT_MESSAGE_ALLOCATE_BUFFER,
    NULL,
    errorCode,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPSTR)&message,
    0,
    NULL
  );

  if(chars > 0 && message != nullptr) {
    result.append(message);
    LocalFree(message);
  } else {
    result = "Unknown error code: " + std::to_string(errorCode);
  }
  return result;
}

bool ManagerRequest() {
  std::string request = "";
  if(PipeRead(request)) {
    if(request == "Modify") {
      g_server.Close();
      Configure();
    } else if(request == "Close") {
      return true;
    }
  }
  return false;
}

void Configure() {
  g_server.SetErrorHandler(ErrorHandler);
  g_server.SetUpdateHandler(UpdateHandler);
  g_server.SetOnRead(OnRead);
  while(true) {
    while(true) {
      if(g_server.SetServerIP(GetConfig("GetIP"))) {
        break;
      }
    }
    while(true) {
      if(g_server.SetServerPort(GetConfig("GetPort"))) {
        break;
      }
    }
    while(true) {
      if(g_server.SetListenBacklog(GetConfig("GetLstnBklg"))) {
        break;
      }
    }
    while(true) {
      if(g_server.SetMaxConnections(GetConfig("GetMaxConn"))) {
        break;
      }
    }
    if(g_server.Open()) {
      break;
    }
  }
  PipeWrite("OK");
}

std::string GetConfig(const std::string& param) {
  while(!PipeWrite(param)) {
    CheckManager();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  std::string value;
  while(true) {
    if(PipeRead(value)) {
      return Trim(value);
    }
    if(!CheckManager()) {
      PrintToConsole("Manager process has exited. Exiting...");
      return Trim(GetString(param + ": "));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return std::string{};
}

std::string Trim(const std::string& str) {
  auto start = std::find_if_not(str.begin(), str.end(), [](unsigned char c) { return std::isspace(c); });
  auto end = std::find_if_not(str.rbegin(), str.rend(), [](unsigned char c) { return std::isspace(c); }).base();
  return (start < end) ? std::string(start, end) : std::string{};
}

void Close() {
  g_server.Close();
  if(g_pipeRead && g_pipeRead != INVALID_HANDLE_VALUE) {
    CloseHandle(g_pipeRead);
    g_pipeRead = INVALID_HANDLE_VALUE;
  }
  if(g_pipeWrite && g_pipeWrite != INVALID_HANDLE_VALUE) {
    CloseHandle(g_pipeWrite);
    g_pipeWrite = INVALID_HANDLE_VALUE;
  }
  exit(0);
}

std::string GetString(std::string prompt) {
  std::string input = "";
  while(true) {
    input = "";
    std::cout << prompt;
    std::getline(std::cin, input);
    if(std::cin.fail()) {
      std::cin.clear();
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      std::cout << "Error: Invalid response. Please try again!" << std::endl;
      continue;
    }
    if(input != "") {
      break;
    } else {
      std::cout << "Error: Invalid response. Please try again!" << std::endl;
    }
  }
  return input;
}

int GetInt(std::string prompt, int minVal, int maxVal) {
  int value = 0;
  while(true) {
    value = 0;
    std::string input = GetString(prompt);
    try {
      value = std::stoi(input);
    } catch(const std::invalid_argument& e) {
      std::cout << "Error: " << e.what() << " Value must be between " << minVal << " and " << maxVal << ". Please try again!" << std::endl;
      continue;
    } catch(const std::out_of_range& e) {
      std::cout << "Error: " << e.what() << " Value must be between " << minVal << " and " << maxVal << ". Please try again!" << std::endl;
      continue;
    }
    if(value >= minVal && value <= maxVal) {
      break;
    } else {
      std::cout << "Error: Value must be between " << minVal << " and " << maxVal << ". Please try again!" << std::endl;
    }
  }
  return value;
}
