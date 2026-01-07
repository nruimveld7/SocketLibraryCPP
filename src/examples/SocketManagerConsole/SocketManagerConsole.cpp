#include <iostream>
#include <string>
#include <limits>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <thread>
#include <mutex>
#include <optional>
#define NOMINMAX
#include <Windows.h>

enum Protocol {
  TCP,
  UDP
};

enum Role {
  CLIENT,
  SERVER
};

enum Option {
  OPEN,
  MODIFY,
  CLOSE
};

struct Socket {
  std::string name = "";
  HANDLE processHandle = nullptr;
  DWORD processID = 0;
  HANDLE pipeRead = INVALID_HANDLE_VALUE;
  HANDLE pipeWrite = INVALID_HANDLE_VALUE;

  bool operator==(const Socket& other) const {
    return name == other.name &&
      processHandle == other.processHandle &&
      processID == other.processID &&
      pipeWrite == other.pipeWrite &&
      pipeRead == other.pipeRead;
  }
};

void RemoveAllClosed();
void RemoveClosed(std::vector<Socket>& sockets, std::mutex& socketsLock);
bool GetLock(Protocol protocol, Role role, std::mutex*& lockOut);
bool GetSockets(Protocol protocol, Role role, std::vector<Socket>*& socketsOut);
void PrintProtocols();
Protocol GetProtocol();
std::string GetProtocolStr(Protocol protocol);
void PrintRoles();
Role GetRole();
std::string GetRoleStr(Role role);
void PrintOptions();
Option GetOption();
std::string GetOptionStr(Option option);
void OptionHandler(Protocol protocol, Role role, Option option);
void SocketOpen(std::vector<Socket>& sockets, Protocol protocol, Role role);
void SocketModify(std::vector<Socket>& sockets, Protocol protocol, Role role);
void SocketClose(std::vector<Socket>& sockets, Protocol protocol, Role role);
void PrintSocketNames(const std::vector<Socket>& sockets);
Socket& GetSocketByName(std::vector<Socket>& sockets);
void SocketClose(std::vector<Socket>& sockets);
void SocketClose(Socket& socket, std::vector<Socket>& sockets);
bool SpawnSocket(
  const std::string& exePath,
  const std::string& socketName,
  const std::string& socketType,
  const std::string& socketRole,
  Socket& socket
);
bool PipeRead(std::string& data, HANDLE& pipe);
bool PipeWrite(const std::string& data, HANDLE& pipe);
bool ConfigSocket(Socket& socket);
std::string DecodeError(int errorCode);
std::string GetString(std::string prompt);
int GetInt(
  std::string prompt,
  int minVal = std::numeric_limits<int>::min(),
  int maxVal = std::numeric_limits<int>::max()
);
std::string RemoveSpaces(const std::string& text);
std::wstring StringToWString(const std::string& str);

std::vector<Socket> tcpClients;
std::mutex tcpClientsLock;
std::vector<Socket> tcpServers;
std::mutex tcpServersLock;
std::vector<Socket> udpClients;
std::mutex udpClientsLock;
std::vector<Socket> udpServers;
std::mutex udpServersLock;

int main() {
  std::thread monitor = std::thread(RemoveAllClosed);
  monitor.detach();
  while(true) {
    Protocol protocol = GetProtocol();
    std::cout << std::endl;
    Role role = GetRole();
    std::cout << std::endl;
    Option option = GetOption();
    std::cout << std::endl;
    system("cls");
    std::mutex* lockMutex;
    if(GetLock(protocol, role, lockMutex)) {
      if(!(lockMutex->try_lock())) {
        std::cout << "Waiting for cleanup to finish..." << std::endl;
        std::lock_guard<std::mutex> lock(*lockMutex);
        OptionHandler(protocol, role, option);
      } else {
        std::lock_guard<std::mutex> lock(*lockMutex, std::adopt_lock);
        OptionHandler(protocol, role, option);
      }
      std::cout << std::endl;
    } else {
      std::cout << "Error fetching lock for this type of socket... Please try again!" << std::endl;
    }
  }
}

void RemoveAllClosed() {
  while(true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    RemoveClosed(tcpClients, tcpClientsLock);
    RemoveClosed(tcpServers, tcpServersLock);
    RemoveClosed(udpClients, udpClientsLock);
    RemoveClosed(udpServers, udpServersLock);
  }
}

void RemoveClosed(std::vector<Socket>& sockets, std::mutex& socketsLock) {
  std::lock_guard<std::mutex> lock(socketsLock);
  for(auto it = sockets.begin(); it != sockets.end();) {
    DWORD exitCode;
    if(!GetExitCodeProcess(it->processHandle, &exitCode) || exitCode != STILL_ACTIVE) {
      //std::cout << "Process " << it->processID << " has exited.\n";
      if(it->processHandle != nullptr && it->processHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(it->processHandle);
      }
      it = sockets.erase(it);
    } else {
      ++it;
    }
  }
}

bool GetLock(Protocol protocol, Role role, std::mutex*& lockOut) {
  switch(protocol) {
    case TCP:
      switch(role) {
        case CLIENT:
          lockOut = &tcpClientsLock;
          return true;
        case SERVER:
          lockOut = &tcpServersLock;
          return true;
        default:
          break;
      }
      break;
    case UDP:
      switch(role) {
        case CLIENT:
          lockOut = &udpClientsLock;
          return true;
        case SERVER:
          lockOut = &udpServersLock;
          return true;
        default:
          break;
      }
      break;
    default:
      break;
  }
  return false;
}

bool GetSockets(Protocol protocol, Role role, std::vector<Socket>*& socketsOut) {
  switch(protocol) {
    case TCP:
      switch(role) {
        case CLIENT:
          socketsOut = &tcpClients;
          return true;
        case SERVER:
          socketsOut = &tcpServers;
          return true;
        default:
          break;
      }
      break;
    case UDP:
      switch(role) {
        case CLIENT:
          socketsOut = &udpClients;
          return true;
        case SERVER:
          socketsOut = &udpServers;
          return true;
        default:
          break;
      }
      break;
    default:
      break;
  }
  return false;
}

void PrintProtocols() {
  std::cout << "Available protocols:" << std::endl;
  std::cout << "TCP" << std::endl;
  std::cout << "UDP" << std::endl;
}

Protocol GetProtocol() {
  while(true) {
    PrintProtocols();
    std::string protocol = GetString("Please select a protocol: ");
    if(protocol == "TCP") {
      return TCP;
    } else if(protocol == "UDP") {
      return UDP;
    }
  }
}

std::string GetProtocolStr(Protocol protocol) {
  if(protocol == TCP) {
    return "TCP";
  } else if(protocol == UDP) {
    return "UDP";
  }
  return "";
}

void PrintRoles() {
  std::cout << "Available roles:" << std::endl;
  std::cout << "Client" << std::endl;
  std::cout << "Server" << std::endl;
}

Role GetRole() {
  while(true) {
    PrintRoles();
    std::string role = GetString("Please select a role: ");
    if(role == "Client") {
      return CLIENT;
    } else if(role == "Server") {
      return SERVER;
    }
  }
}

std::string GetRoleStr(Role role) {
  if(role == CLIENT) {
    return "Client";
  } else if(role == SERVER) {
    return "Server";
  }
  return "";
}

void PrintOptions() {
  std::cout << "Available Options:" << std::endl;
  std::cout << "Open" << std::endl;
  std::cout << "Modify" << std::endl;
  std::cout << "Close" << std::endl;
}

Option GetOption() {
  while(true) {
    PrintOptions();
    std::string option = GetString("Please select an option: ");
    if(option == "Open") {
      return OPEN;
    } else if(option == "Modify") {
      return MODIFY;
    } else if(option == "Close") {
      return CLOSE;
    }
  }
}

std::string GetOptionStr(Option option) {
  if(option == OPEN) {
    return "Open";
  } else if(option == MODIFY) {
    return "Modify";
  } else if(option == CLOSE) {
    return "Close";
  }
  return "";
}

void OptionHandler(Protocol protocol, Role role, Option option) {
  std::vector<Socket>* sockets;
  if(!GetSockets(protocol, role, sockets)) {
    std::cout << "Error fetching sockets list..." << std::endl << std::endl;
  }
  switch(option) {
    case OPEN:
      SocketOpen(*sockets, protocol, role);
      break;
    case MODIFY:
      SocketModify(*sockets, protocol, role);
      break;
    case CLOSE:
      SocketClose(*sockets, protocol, role);
      break;
    default:
      std::cout << "Error handling the selected option..." << std::endl << std::endl;
      break;
  }
}

void SocketOpen(std::vector<Socket>& sockets, Protocol protocol, Role role) {
  sockets.emplace_back();
  Socket& socket = sockets.back();
  std::string name;
  while(true) {
    name = GetString("Enter a name for this socket: ");
    bool found = false;
    for(const auto& other : sockets) {
      if(other.name == name) {
        found = true;
        std::cout << "Error: This name is already in use. Try again!" << std::endl;
        break;
      }
    }
    if(!found) {
      break;
    }
  }
  socket.name = name;
  std::string exeName = GetProtocolStr(protocol) + GetRoleStr(role) + "Console.exe";
  if(SpawnSocket(exeName, name, GetProtocolStr(protocol), GetRoleStr(role), socket)) {
    if(!ConfigSocket(socket)) {
      sockets.pop_back();
      std::cout << "Error configuring socket. Please try again!" << std::endl << std::endl;
    }
  } else {
    sockets.pop_back();
    std::cout << "Error creating socket. Please try again!" << std::endl << std::endl;
  }
}

void SocketModify(std::vector<Socket>& sockets, Protocol protocol, Role role) {
  if(sockets.empty()) {
    std::string error = "No " + GetProtocolStr(protocol) + " " + GetRoleStr(role) + "s to modify...";
    std::cout << error << std::endl << std::endl;
    return;
  }
  Socket& socket = GetSocketByName(sockets);
  PipeWrite("Modify", socket.pipeWrite);
  if(!ConfigSocket(socket)) {
    std::cout << "Error modifying socket. Please try again!" << std::endl << std::endl;
  }
}

void SocketClose(std::vector<Socket>& sockets, Protocol protocol, Role role) {
  if(sockets.empty()) {
    std::string error = "No " + GetProtocolStr(protocol) + " " + GetRoleStr(role) + "s to close...";
    std::cout << error << std::endl << std::endl;
    return;
  }
  Socket& socket = GetSocketByName(sockets);
  PipeWrite("Close", socket.pipeWrite);
}

void PrintSocketNames(std::vector<Socket>& sockets) {
  if(sockets.empty()) {
    return;
  }
  std::cout << "Socket names:" << std::endl;
  for(auto& socket : sockets) {
    std::cout << socket.name << std::endl;
  }
}

Socket& GetSocketByName(std::vector<Socket>& sockets) {
  if(sockets.empty()) {
    throw std::invalid_argument("The vector of sockets is empty.");
  }
  while(true) {
    PrintSocketNames(sockets);
    std::string name = GetString("Enter the name of the desired socket: ");
    for(auto& socket : sockets) {
      if(socket.name == name) {
        return socket;
      }
    }
    std::cout << "No sockets with the name '" << name << "'. Please try again!" << std::endl << std::endl;
  }
}

void SocketClose(std::vector<Socket>& sockets) {
  if(sockets.empty()) {
    return;
  }
  auto& socket = GetSocketByName(sockets);
  SocketClose(socket, sockets);
}

void SocketClose(Socket& socket, std::vector<Socket>& sockets) {
  auto it = std::find(sockets.begin(), sockets.end(), socket);
  if(it != sockets.end()) {
    sockets.erase(it);
  } else {
    std::cout << "Socket not found!" << std::endl;
  }
}

bool SpawnSocket(
  const std::string& exePath,
  const std::string& socketName,
  const std::string& socketType,
  const std::string& socketRole,
  Socket& socket
) {
  std::string title = socketType + " " + socketRole + " Socket - " + socketName;
  std::wstring wTitle = StringToWString(title);
  SECURITY_ATTRIBUTES sa = { 0 };
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;

  HANDLE clientRead;
  HANDLE clientWrite;
  if(!CreatePipe(&socket.pipeRead, &clientWrite, &sa, 0)) {
    std::cerr << "Failed to create read pipe. Error: " << DecodeError(GetLastError()) << std::endl;
    return false;
  }

  if(!CreatePipe(&clientRead, &socket.pipeWrite, &sa, 0)) {
    std::cerr << "Failed to create write pipe. Error: " << DecodeError(GetLastError()) << std::endl;
    return false;
  }

  SetHandleInformation(socket.pipeRead, HANDLE_FLAG_INHERIT, 0);  // Parent keeps read handle
  SetHandleInformation(socket.pipeWrite, HANDLE_FLAG_INHERIT, 0);

  std::cout << "Read Pipe: " << socket.pipeRead << std::endl;
  std::cout << "Write Pipe: " << socket.pipeWrite << std::endl;

  STARTUPINFO si = { 0 };
  si.cb = sizeof(STARTUPINFO);
  si.lpTitle = &wTitle[0];
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_SHOW;
  DWORD procID = GetCurrentProcessId();
  std::wstring cmdLine = StringToWString(exePath) + L" ";
  cmdLine += std::to_wstring(reinterpret_cast<uintptr_t>(clientRead)) + L" ";
  cmdLine += std::to_wstring(reinterpret_cast<uintptr_t>(clientWrite)) + L" ";
  cmdLine += std::to_wstring(procID);
  PROCESS_INFORMATION pi = { 0 };
  if(CreateProcess(NULL, &cmdLine[0], NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
    std::cout << "Process created successfully: PID = " << pi.dwProcessId << std::endl;
    socket.processHandle = pi.hProcess;
    socket.processID = pi.dwProcessId;
    CloseHandle(pi.hThread);
    std::string data = "";
    while(data != "OK") {
      if(PipeRead(data, socket.pipeRead)) {
        std::cout << "Received " << data << std::endl;
      } else {
        std::cerr << "Failed to read from pipe!" << std::endl;
        return false;
      }
    }
    return true;
  }
  std::cerr << "Failed to create process. Error: " << DecodeError(GetLastError()) << std::endl;
  return false;
}

bool PipeRead(std::string& data, HANDLE& pipe) {
  char buffer[256];
  DWORD bytesRead;
  BOOL success = ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, NULL);
  if(!success || bytesRead == 0) {
    std::cerr << "Failed to read from pipe! Error: " << DecodeError(GetLastError()) << std::endl;
    return false;
  }
  data.assign(buffer, bytesRead);
  return true;
}

bool PipeWrite(const std::string& data, HANDLE& pipe) {
  DWORD bytesWritten;
  BOOL success = WriteFile(pipe, data.c_str(), static_cast<DWORD>(data.size()), &bytesWritten, NULL);
  if(!success || bytesWritten != data.size()) {
    std::cerr << "Failed to write to pipe! Error: " << DecodeError(GetLastError()) << std::endl;
    return false;
  }
  return true;
}

bool ConfigSocket(Socket& socket) {
  std::string command = "";
  while(command != "OK") {
    if(PipeRead(command, socket.pipeRead)) {
      std::cout << "Received " << command << std::endl;
      std::string response = "";
      if(command == "GetIP") {
        while(true) {
          response = GetString("Enter the IP address: ");
          if(response.size() > 0 && response.size() < 16) {
            break;
          }
          std::cout << "Error: Invalid IP address detected. Please try again!" << std::endl;
        }
      } else if(command == "GetPort") {
        response = std::to_string(GetInt("Enter the port number: ", 0, 65535));
      } else if(command == "GetMsgLen") {
        response = std::to_string(GetInt("Enter the maximum message length: ", 1, 100000));
      } else if(command == "GetLstnBklg") {
        response = std::to_string(GetInt("Enter the listen backlog size: ", 1, 20));
      } else if(command == "GetMaxConn") {
        response = std::to_string(GetInt("Enter the maximum allowed connections: ", 1, 20));
      } else if(command == "GetConnDelay") {
        response = std::to_string(GetInt("Enter the delay (seconds) between connection attempts: ", 0, std::numeric_limits<int>::max()));
      } else if(command != "OK") {
        std::cout << "Unrecognized command" << std::endl;
        response = "NOT OK";
      }
      PipeWrite(response, socket.pipeWrite);
    } else {
      std::cerr << "Failed to read from pipe!" << std::endl;
      return false;
    }
  }
  return true;
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

std::string RemoveSpaces(const std::string& text) {
  std::string result = text;
  result.erase(std::remove(result.begin(), result.end(), ' '), result.end());
  return result;
}

std::wstring StringToWString(const std::string& str) {
  return std::wstring(str.begin(), str.end());
}
