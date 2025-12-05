# Simple usage example
add_executable(simple_usage simple_usage.cpp)

target_link_libraries(simple_usage
    PRIVATE status-keycard-qt
)

# Install
install(TARGETS simple_usage
    RUNTIME DESTINATION bin/examples
)

