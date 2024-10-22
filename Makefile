OBJS=des.o
TARGET=des
CXXFLAGS=-O2 -Wall

ifdef DEBUG
CXXFLAGS+=-g -DDEBUG
$(TARGET) : $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $<
endif
$(OBJS) : des.cpp des.h des_const.h
	$(CXX) $(CXXFLAGS) -c des.cpp
clean:
	rm -f $(OBJS) $(TARGET)