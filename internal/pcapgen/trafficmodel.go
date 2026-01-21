package pcapgen

import "math"

func durationScalar(hour float64, weekend bool) float64 {
	if hour < 0 || hour >= 24 {
		return 0
	}
	hour = math.Mod(hour+1, 24)

	x := make([]float64, 25)
	for i := 0; i <= 24; i++ {
		x[i] = float64(i)
	}

	var y []float64
	if weekend {
		y = []float64{0, .4, 0, 0, 0, 0, 0, 0, .1, .2, .5, .45, .45, .5, .45, .45, .45, .45, .5, .2, 0, 0, 0, 0, 0}
	} else {
		y = []float64{0, .4, 0, 0, 0, 0, 0, .1, .2, .4, .95, .9, .9, .95, .9, .9, .9, .9, .95, .4, .1, 0, 0, 0, 0}
	}

	spline := newCubicSpline(x, y)
	result := 1 - spline.eval(hour)
	if result < 0 {
		result = 0
	} else if result > 1 {
		result = 1
	}
	return result
}

type cubicSpline struct {
	x, a, b, c, d []float64
}

func newCubicSpline(x, y []float64) *cubicSpline {
	n := len(x)
	a := make([]float64, n)
	copy(a, y)
	b := make([]float64, n)
	c := make([]float64, n)
	d := make([]float64, n)
	h := make([]float64, n-1)
	alpha := make([]float64, n-1)

	for i := 0; i < n-1; i++ {
		h[i] = x[i+1] - x[i]
	}
	for i := 1; i < n-1; i++ {
		alpha[i] = (3/h[i])*(a[i+1]-a[i]) - (3/h[i-1])*(a[i]-a[i-1])
	}

	l := make([]float64, n)
	mu := make([]float64, n)
	z := make([]float64, n)
	l[0] = 1
	mu[0] = 0
	z[0] = 0

	for i := 1; i < n-1; i++ {
		l[i] = 2*(x[i+1]-x[i-1]) - h[i-1]*mu[i-1]
		mu[i] = h[i] / l[i]
		z[i] = (alpha[i] - h[i-1]*z[i-1]) / l[i]
	}
	l[n-1] = 1
	z[n-1] = 0
	c[n-1] = 0

	for j := n - 2; j >= 0; j-- {
		c[j] = z[j] - mu[j]*c[j+1]
		b[j] = (a[j+1]-a[j])/h[j] - h[j]*(c[j+1]+2*c[j])/3
		d[j] = (c[j+1] - c[j]) / (3 * h[j])
	}

	return &cubicSpline{x: x, a: a, b: b, c: c, d: d}
}

func (s *cubicSpline) eval(x float64) float64 {
	n := len(s.x)
	if x <= s.x[0] {
		return s.a[0]
	}
	if x >= s.x[n-1] {
		return s.a[n-1]
	}

	idx := 0
	for i := 0; i < n-1; i++ {
		if x >= s.x[i] && x <= s.x[i+1] {
			idx = i
			break
		}
	}
	dx := x - s.x[idx]
	return s.a[idx] + s.b[idx]*dx + s.c[idx]*dx*dx + s.d[idx]*dx*dx*dx
}
