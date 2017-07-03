#pragma once
#include <stdint.h>

class intrin
{
public:
	static unsigned __int64 byteswap(_In_ unsigned __int64 v) {
		return _byteswap_uint64(v);
	}
	static __int64 byteswap(_In_ __int64 v) {
		return static_cast<__int64>(byteswap(static_cast<unsigned __int64>(v)));
	}
	static unsigned long byteswap(_In_ unsigned long v) {
		return _byteswap_ulong(v);
	}
	static long byteswap(_In_ long v) {
		return static_cast<long>(byteswap(static_cast<unsigned long>(v)));
	}
	static unsigned int byteswap(_In_ unsigned int v) {
		return _byteswap_ulong(static_cast<unsigned long>(v));
	}
	static int byteswap(_In_ int v) {
		return static_cast<int>(byteswap(static_cast<unsigned long>(v)));
	}
	static unsigned short byteswap(_In_ unsigned short v) {
		return _byteswap_ushort(v);
	}
	static short byteswap(_In_ short v) {
		return static_cast<short>(byteswap(static_cast<unsigned short>(v)));
	}
};

template<typename _Type = void> class calculator
{
public:
	typedef _Type type;

protected:
	intptr_t _size;

public:
	calculator(intptr_t _init = 0) : _size(_init) {}
	template<typename _ValType = intptr_t> _ValType get_length() {
		return static_cast<_ValType>(this->_size);
	}
	template<typename _ValType = intptr_t> _ValType length() {
		return static_cast<_ValType>(this->_size);
	}
	template<typename _ValType = intptr_t> _ValType rlength() {
		return intrin::byteswap(this->length<_ValType>());
	}
	template<typename _Type = uint8_t> calculator<_Type> &push(calculator<_Type> &) {
		this->_size += static_cast<intptr_t>(sizeof(_Type));
		return *reinterpret_cast<calculator<_Type> *>(nullptr);
	}
	template<typename _Type> calculator<_Type> &push() {
		this->_size += static_cast<intptr_t>(sizeof(_Type));
		return *reinterpret_cast<calculator<_Type> *>(nullptr);
	}
	template<typename _ValType> _ValType push(_ValType v) {
		this->_size += static_cast<intptr_t>(v);
		return v;
	}
	template<typename _ValType> _ValType pop(_ValType v) {
		this->_size -= static_cast<intptr_t>(v);
		return v;
	}
};

#pragma pack(1)
template<class... _Types> class __declspec(align(1)) builder;
#pragma pack(1)
template<> class __declspec(align(1)) builder<>
{
protected:
	intptr_t _size;

public:
	builder() : _size(0) {}

public:
	template<typename _ValType = intptr_t> _ValType get_length() {
		return static_cast<_ValType>(this->_size);
	}
	template<typename _ValType = intptr_t> _ValType length() {
		return static_cast<_ValType>(this->_size);
	}
	template<typename _ValType = intptr_t> _ValType rlength() {
		return intrin::byteswap(this->length<_ValType>());
	}
	template<typename _ValType = intptr_t> constexpr static _ValType size() {
		return static_cast<_ValType>(sizeof(builder));
	}
	template<typename _ValType = intptr_t> static _ValType rsize() {
		return intrin::byteswap(builder::size<_ValType>());
	}
	template<typename _Type> _Type *first() {
#ifdef assert
		assert(reinterpret_cast<char *>(this) == reinterpret_cast<char *>(&this->_size));
#endif // assert
		return reinterpret_cast<_Type *>(reinterpret_cast<char *>(this) + sizeof(this->_size));
	}
	template<typename _Type> _Type *current() {
		return reinterpret_cast<_Type *>(this->first<char>() + this->_size);
	}
	template<typename _Type = uint8_t> _Type *get(calculator<_Type> &) {
		return this->get<_Type>(sizeof(_Type));
	}
	template<typename _Type = uint8_t> _Type *get(intptr_t bytes) {
		auto p = this->current<_Type>();
		this->_size += bytes;
		return p;
	}
	template<typename _Type> _Type *get() {
		return this->get<_Type>(sizeof(_Type));
	}
	builder &seek(intptr_t bytes = 0) {
		this->_size += bytes;
		return *this;
	}
	builder &seek_back(intptr_t bytes = 0) {
		this->_size -= bytes;
		return *this;
	}
	builder &write(const void *val, uintptr_t sz) {
		memcpy(this->get(sz), val, sz);
		return *this;
	}
	template<typename _Type> builder &write(_Type &val) {
		return this->write(&val, sizeof(_Type));
	}
	builder &append(builder<> &packet) {
		memcpy(this->get(packet.length()), packet.first<void>(), packet.length());
		return *this;
	}
};
#pragma pack(1)
template<class _This, class... _Rest> class __declspec(align(1)) builder<_This, _Rest...> : public builder<_Rest...>
{
protected:
	char _data[sizeof(_This)];

public:
	template<typename _ValType = intptr_t> bool validate() {
#ifdef assert
		assert(this->length() <= this->size());
#endif // assert
		return this->length() <= this->size();
	}
	template<typename _ValType = intptr_t> constexpr static _ValType size() {
		return static_cast<_ValType>(sizeof(builder) - sizeof(builder::_size));
	}
	template<typename _ValType = intptr_t> static _ValType rsize() {
		return intrin::byteswap(builder::size<_ValType>());
	}
	_This *left() {
		return reinterpret_cast<_This *>(this->_data);
	}
};
#pragma pack()