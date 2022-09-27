# Changes to make Jackalope become Sandup - Windows Service Fuzzing

- *tinyinstrumentation.cpp:* `RunResult TinyInstInstrumentation::Run(int argc, char **argv, uint32_t init_timeout, uint32_t timeout)`
  - this function needs to change to use `instrumentation->Attach` instead of `instrumentation->Debug`
