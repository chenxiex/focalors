SRCS=des.cpp main.cpp bcm.cpp type.cpp aes.cpp
OBJS = $(SRCS:.cpp=.o)
DEPS = $(SRCS:.cpp=.d)
TARGET=crypt
CXXFLAGS=-O3 -Wall -Iinclude/

ifdef DEBUG
CXXFLAGS+=-g
endif

.PHONY: clean

$(TARGET) : $(OBJS) 
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.d: %.cpp
	$(CXX) $(CXXFLAGS) -MM -MF $@ $<

include $(DEPS)

clean:
	-rm $(OBJS) $(TARGET) $(DEPS)