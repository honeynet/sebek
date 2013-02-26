#ifndef SINGLETON_H
#define SINGLETON_H

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// Stupid VC++ STL
#pragma warning (disable: 4786)

template<class T>
class CSingleton 
{
public:
    static T& Instance();
		static void Release();
protected:
    CSingleton();
private:
    static T *pinstance;
};

template<class T> T *CSingleton<T>::pinstance = 0;// initialize pointer
template<class T> T& CSingleton<T>::Instance()
{
	if (pinstance == 0)
		pinstance = new T;

	return *pinstance;
}

template<class T>
CSingleton<T>::CSingleton<T>()  {
}

template<class T> void CSingleton<T>::Release() 
{
	if(pinstance != 0) {
		delete pinstance;
		pinstance = 0;
	}
}

#endif
