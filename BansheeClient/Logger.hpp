#pragma once

#include <string>
#include <iostream>
#include <stdlib.h>

#define PROMPT "$ BANSHEE > "

bool __tryParse(const std::string& input, int& output) 
{
	try 
	{
		output = std::stoi(input);
	}
	catch (std::invalid_argument) 
	{
		return false;
	}
	return true;
}

std::string AskInput(const std::string& msg)
{
	std::cout << msg << "\n" << PROMPT;
	std::string choice;
	std::getline(std::cin, choice);
	return choice;
}

std::string AskInputNoPrompt(const std::string& msg)
{
	std::cout << msg;
	std::string choice;
	std::getline(std::cin, choice);
	return choice;
}

int getIntFromUser(const std::string& prompt)
{
	std::cout << prompt;
	std::string input;
	int n;

	std::getline(std::cin, input);

	while (!__tryParse(input, n))
	{
		std::cout << "Bad entry. Enter a NUMBER: ";
		std::getline(std::cin, input);
	}

	return n;
}

enum Color 
{
	DBLUE = 1, GREEN, GREY, DRED, DPURP, BROWN, LGREY, DGREY, BLUE, LIMEG, TEAL,
	RED, PURPLE, YELLOW, WHITE, B_B
};

void SetConsoleColour(WORD* Attributes, WORD Colour)
{
	CONSOLE_SCREEN_BUFFER_INFO Info;
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hStdout, &Info);
	*Attributes = Info.wAttributes;
	SetConsoleTextAttribute(hStdout, Colour);
}

void ResetConsoleColour(WORD Attributes)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), Attributes);
}

void LogError(const std::string& msg)
{
	WORD attributes = 0;
	std::cout << "\nBanshee::[";
	SetConsoleColour(&attributes, RED);
	std::cout << "!";
	ResetConsoleColour(attributes);
	std::cout << "] " << msg << ". GetLastError: " << GetLastError() << std::endl;
}

void LogWarning(const std::string& msg)
{
	WORD attributes = 0;
	std::cout << "Banshee::[";
	SetConsoleColour(&attributes, YELLOW);
	std::cout << "-";
	ResetConsoleColour(attributes);
	std::cout << "] " << msg << std::endl;
}

void LogInfo(const std::string& msg)
{
	std::cout << "Banshee::[*] " << msg << std::endl;
}