#include <iostream>
#include <string>
#include <algorithm>
#include <limits>
#include <thread>
#include <mutex>

#define NOMINMAX
#define UDPSOCKET
#include "SocketLibrary.h"
#include <Windows.h>

using namespace SocketLibrary;

void OnRead(unsigned char* message, size_t byteCount, sockaddr_in sender);
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
UDPClientSocket g_client;
std::mutex g_managerLock;
DWORD g_managerPid;

int main(int argc, char* argv[]) {
  if(argc == 4) {
    g_pipeRead = reinterpret_cast<HANDLE>(std::stoull(argv[1]));
    g_pipeWrite = reinterpret_cast<HANDLE>(std::stoull(argv[2]));
    g_managerPid = std::stoi(argv[3]);
    g_spawned = true;
  }
  if(g_pipeRead == INVALID_HANDLE_VALUE || g_pipeWrite == INVALID_HANDLE_VALUE) {
    g_pipeRead = GetStdHandle(STD_INPUT_HANDLE);
    g_pipeWrite = GetStdHandle(STD_OUTPUT_HANDLE);
  }
  std::cout << "Read Pipe: " << g_pipeRead << std::endl;
  std::cout << "Write Pipe: " << g_pipeWrite << std::endl;
  PipeWrite("OK");
  Configure();
  if(!g_spawned) {
    std::cout << "Between messages, enter '/m' or '/c' to modify or close the socket respectively." << std::endl << std::endl;
  }
  std::cout << "Ready To Communicate" << std::endl;
  std::cout << "Enter '/n' to communicate with a new server" << std::endl;
  std::cout << "Otherwise, begin typing the message to send" << std::endl;
  if(g_spawned) {
    std::thread monitor = std::thread(ManagerHandler);
    monitor.detach();
  }
  while(true) {
    std::string input = "";
    std::getline(std::cin, input);
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

void OnRead(unsigned char* message, size_t byteCount, sockaddr_in sender) {
  if(message == nullptr) {
    PrintToConsole("Invalid Message");
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
  if(input == "/n") {
    std::cout << "Setting up communications with a new server:" << std::endl;
    std::string targetIP = "";
    while(true) {
      targetIP = GetString("Enter the target IP address: ");
      if(Socket::CheckIP(targetIP)) {
        break;
      }
    }
    int targetPort = 0;
    while(true) {
      targetPort = GetInt("Enter the target port: ");
      if(Socket::CheckPort(targetPort)) {
        break;
      }
    }
    std::cout << "Enter the message to send: ";
    std::getline(std::cin, input);
    g_client.Send(input.c_str(), static_cast<int>(input.size()), targetIP, targetPort);
  } else if(input == "/m" && !g_spawned) {
    g_client.Close();
    Configure();
  } else if(input == "/c" && !g_spawned) {
    g_client.Close();
  } else {
    std::cout << "Replying with: " << input << std::endl;
    g_client.Send(input.c_str(), static_cast<int>(input.size()));
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
  char buffer[256];
  DWORD bytesRead;
  BOOL success = ReadFile(g_pipeRead, buffer, sizeof(buffer), &bytesRead, NULL);
  if(!success || bytesRead == 0) {
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
      g_client.Close();
      Configure();
    } else if(request == "Close") {
      return true;
    }
  }
  return false;
}

void Configure() {
  g_client.SetErrorHandler(ErrorHandler);
  g_client.SetUpdateHandler(UpdateHandler);
  g_client.SetOnRead(OnRead);
  while(true) {
    while(true) {
      if(g_client.SetServerIP(GetConfig("GetIP"))) {
        break;
      }
    }
    while(true) {
      if(g_client.SetServerPort(GetConfig("GetPort"))) {
        break;
      }
    }
    if(g_client.Open()) {
      break;
    }
  }
  PipeWrite("OK");
}

std::string GetConfig(const std::string& param) {
  while(!PipeWrite(param));
  std::string value = "";
  while(!PipeRead(value)) {
    CheckManager();
  }
  return Trim(value);
}

std::string Trim(const std::string& str) {
  auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
  auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();
  return (start < end) ? std::string(start, end) : "";
}

void Close() {
  g_client.Close();
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
