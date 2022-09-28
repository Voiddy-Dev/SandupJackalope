/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define _CRT_SECURE_NO_WARNINGS

#include "common.h"
#include "tinyinstinstrumentation.h"
#include "litecov.h"

#include <sstream>

void TinyInstInstrumentation::Init(int argc, char **argv)
{
  instrumentation = new LiteCov();
  instrumentation->Init(argc, argv);

  persist = GetBinaryOption("-persist", argc, argv, false);
  num_iterations = GetIntOption("-iterations", argc, argv, 1);

  oldpid = -1;
}

RunResult TinyInstInstrumentation::AttachWithCrashAnalysis(int argc, char **argv, char *service_name, uint32_t init_timeout, uint32_t timeout)
{
  // clean process when reproducing crashes
  instrumentation->Kill();
  // disable instrumentation when reproducing crashes
  instrumentation->DisableInstrumentation();
  RunResult ret = Attach(argc, argv, service_name, init_timeout, timeout);
  instrumentation->Kill();
  instrumentation->EnableInstrumentation();
  return ret;
}

DWORD GetServicePid(char *serviceName)
{
  const auto hScm = OpenSCManager(nullptr, nullptr, NULL);
  const auto hSc = OpenServiceA(hScm, serviceName, SERVICE_QUERY_STATUS);

  SERVICE_STATUS_PROCESS ssp = {};
  DWORD bytesNeeded = 0;
  QueryServiceStatusEx(hSc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);

  CloseServiceHandle(hSc);
  CloseServiceHandle(hScm);

  return ssp.dwProcessId;
}

DWORD FindServicePID(char *service_name, int oldpid)
{
  DWORD pid;
  while (1)
  {
    pid = GetServicePid(service_name);
    if (pid && pid != 0 && oldpid != pid)
      return pid;
    WARN("Could not find target process, retrying after timeout");
    Sleep(10);
  }
}

struct sys_t_arg {
  const char *cmd;
  int timeout;
};

DWORD WINAPI sys_thread_func(void *arg)
{
    sys_t_arg *params = (sys_t_arg *)arg;
    Sleep(params->timeout);
    system(params->cmd);
    // printf(".");
    return 0;
}


RunResult TinyInstInstrumentation::Attach(int argc, char **argv, char *service_name, uint32_t init_timeout, uint32_t timeout)
{
  DebuggerStatus status;
  RunResult ret = OTHER_ERROR;

  std::string cmd;
  for (int i = 0; i < argc; i++)
  {
    // printf("SANDUP - argv[%d] is %s\n", i, argv[i]);
    cmd.append(argv[i]);
    cmd.append(" ");
  }

  if (instrumentation->IsTargetFunctionDefined())
  {
    FATAL("SANDUP - Target function should not be defined...");
  }

  // else clear only when the target function is reached
  instrumentation->ClearCoverage();

  uint32_t timeout1 = timeout;

  // if (instrumentation->IsTargetAlive() && persist)
  // {
  //   status = instrumentation->Continue(timeout1);
  // }
  // else
  // {
  instrumentation->Kill();
  cur_iteration = 0;
  Sleep(init_timeout);
  DWORD pid;
  while (1)
  {
    if (oldpid != -1)
      pid = FindServicePID(service_name, oldpid);
    else
      pid = GetServicePid(service_name);

    if (pid)
      break;
    WARN("Could not find target process, retrying after timeout - oldpid --> -1");
    Sleep(init_timeout);
  }
  // printf("SANDUP - Old PID: %d - Service PID: %d\n", oldpid, pid);
  oldpid = pid;

  // printf("Final command: %s\n", cmd.c_str());
  sys_t_arg torun;
  torun.timeout = timeout1 / 5; // good enough?
  torun.cmd = cmd.c_str();
  HANDLE t_hdl = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sys_thread_func, &torun, 0, NULL);
  status = instrumentation->Attach(pid, timeout1);
  if (t_hdl) CloseHandle(t_hdl);
  // }

  switch (status)
  {
  case DEBUGGER_CRASHED:
    ret = CRASH;
    instrumentation->Kill();
    break;
  case DEBUGGER_HANGED:
    // ret = HANG;
    // instrumentation->Kill();
    ret = OK;
    break;
  case DEBUGGER_PROCESS_EXIT:
    ret = OK;
    if (instrumentation->IsTargetFunctionDefined())
    {
      WARN("Process exit during target function\n");
      ret = HANG;
      FATAL("SANDUP - Target function should not be defined...");
    }
    break;
  case DEBUGGER_TARGET_END:
    if (instrumentation->IsTargetFunctionDefined())
    {
      ret = OK;
      cur_iteration++;
      FATAL("SANDUP - Target function should not be defined...");
    }
    else
    {
      FATAL("Unexpected status received from the debugger\n");
    }
    break;
  default:
    FATAL("Unexpected status received from the debugger\n");
    break;
  }

  return ret;
}

RunResult TinyInstInstrumentation::Run(int argc, char **argv, uint32_t init_timeout, uint32_t timeout)
{
  DebuggerStatus status;
  RunResult ret = OTHER_ERROR;

  if (instrumentation->IsTargetFunctionDefined())
  {
    if (cur_iteration == num_iterations)
    {
      instrumentation->Kill();
      cur_iteration = 0;
    }
  }

  // else clear only when the target function is reached
  if (!instrumentation->IsTargetFunctionDefined())
  {
    instrumentation->ClearCoverage();
  }

  uint32_t timeout1 = timeout;
  if (instrumentation->IsTargetFunctionDefined())
  {
    timeout1 = init_timeout;
  }

  if (instrumentation->IsTargetAlive() && persist)
  {
    status = instrumentation->Continue(timeout1);
  }
  else
  {
    instrumentation->Kill();
    cur_iteration = 0;
    status = instrumentation->Run(argc, argv, timeout1);
  }

  // if target function is defined,
  // we should wait until it is hit
  if (instrumentation->IsTargetFunctionDefined())
  {
    if (status != DEBUGGER_TARGET_START)
    {
      // try again with a clean process
      WARN("Target function not reached, retrying with a clean process\n");
      instrumentation->Kill();
      cur_iteration = 0;
      status = instrumentation->Run(argc, argv, init_timeout);
    }

    if (status != DEBUGGER_TARGET_START)
    {
      switch (status)
      {
      case DEBUGGER_CRASHED:
        FATAL("Process crashed before reaching the target method\n");
        break;
      case DEBUGGER_HANGED:
        FATAL("Process hanged before reaching the target method\n");
        break;
      case DEBUGGER_PROCESS_EXIT:
        FATAL("Process exited before reaching the target method\n");
        break;
      default:
        FATAL("An unknown problem occured before reaching the target method\n");
        break;
      }
    }

    instrumentation->ClearCoverage();

    status = instrumentation->Continue(timeout);
  }

  switch (status)
  {
  case DEBUGGER_CRASHED:
    ret = CRASH;
    instrumentation->Kill();
    break;
  case DEBUGGER_HANGED:
    ret = HANG;
    instrumentation->Kill();
    break;
  case DEBUGGER_PROCESS_EXIT:
    ret = OK;
    if (instrumentation->IsTargetFunctionDefined())
    {
      WARN("Process exit during target function\n");
      ret = HANG;
    }
    break;
  case DEBUGGER_TARGET_END:
    if (instrumentation->IsTargetFunctionDefined())
    {
      ret = OK;
      cur_iteration++;
    }
    else
    {
      FATAL("Unexpected status received from the debugger\n");
    }
    break;
  default:
    FATAL("Unexpected status received from the debugger\n");
    break;
  }

  return ret;
}

RunResult TinyInstInstrumentation::RunWithCrashAnalysis(int argc, char **argv, uint32_t init_timeout, uint32_t timeout)
{
  // clean process when reproducing crashes
  instrumentation->Kill();
  // disable instrumentation when reproducing crashes
  instrumentation->DisableInstrumentation();
  RunResult ret = Run(argc, argv, init_timeout, timeout);
  instrumentation->Kill();
  instrumentation->EnableInstrumentation();
  return ret;
}

void TinyInstInstrumentation::CleanTarget()
{
  instrumentation->Kill();
}

bool TinyInstInstrumentation::HasNewCoverage()
{
  return instrumentation->HasNewCoverage();
}

void TinyInstInstrumentation::GetCoverage(Coverage &coverage, bool clear_coverage)
{
  instrumentation->GetCoverage(coverage, clear_coverage);
}

void TinyInstInstrumentation::ClearCoverage()
{
  instrumentation->ClearCoverage();
}

void TinyInstInstrumentation::IgnoreCoverage(Coverage &coverage)
{
  instrumentation->IgnoreCoverage(coverage);
}

TinyInstInstrumentation::~TinyInstInstrumentation()
{
  instrumentation->Kill();
  delete instrumentation;
}

std::string TinyInstInstrumentation::GetCrashName()
{
  LiteCov::Exception exception = instrumentation->GetLastException();
  std::stringstream stream;
  switch (exception.type)
  {
  case LiteCov::ExceptionType::ACCESS_VIOLATION:
    stream << "access_violation";
    break;
  case LiteCov::ExceptionType::ILLEGAL_INSTRUCTION:
    stream << "illegal_instruction";
    break;
  case LiteCov::ExceptionType::STACK_OVERFLOW:
    stream << "stack_overflow";
    break;
  default:
    stream << "other";
    break;
  }
  stream << "_";
  stream << AnonymizeAddress(exception.ip);
  stream << "_";
  stream << AnonymizeAddress(exception.access_address);
  return stream.str();
}

uint64_t TinyInstInstrumentation::GetReturnValue()
{
  return instrumentation->GetTargetReturnValue();
}
