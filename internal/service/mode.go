package service

type Mode string

const (
	ModeDevelopment Mode = "development"
	ModeTest        Mode = "test"
	ModeProduction  Mode = "production"
)

func (m Mode) IsProduction() bool { return m == ModeProduction }

func (m Mode) IsValid() bool {
	return m == ModeDevelopment || m == ModeTest || m == ModeProduction
}
