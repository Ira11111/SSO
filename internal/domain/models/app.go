package models

type App struct {
	// модель приложения
	Id     int
	Name   string
	Secret string // секрет подписывает токены, нужно подумать куда вынести
}
