OBJS=des.o main.o group-mode.o
TARGET=crypt
CXXFLAGS=-O2 -Wall

ifdef DEBUG
CXXFLAGS=-g -Wall -DDEBUG
endif

$(TARGET) : $(OBJS) 
	$(CXX) $(CXXFLAGS) -o $@ $^
des.o : des.cpp des.h crypt.h group-mode.h
	$(CXX) $(CXXFLAGS) -c $< -o $@
main.o : main.cpp crypt.h group-mode.h
	$(CXX) $(CXXFLAGS) -c $< -o $@
group-mode.o : group-mode.cpp group-mode.h
	$(CXX) $(CXXFLAGS) -c $< -o $@
clean:
	-rm $(OBJS) $(TARGET)