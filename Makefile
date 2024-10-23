OBJS=des.o
TARGET=des
CXXFLAGS=-O2 -Wall

ifdef DEBUG
CXXFLAGS+=-g -DDEBUG
$(TARGET) : $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $<
endif
$(OBJS) : des.cpp des.h crypt.h
	$(CXX) $(CXXFLAGS) -c des.cpp
clean:
	rm $(OBJS) $(TARGET)