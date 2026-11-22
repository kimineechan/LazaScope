//go:build windows

package winui

import (
	"math"
	"syscall"
	"unsafe"
)

// Style is how a paragraph of a Reader is lettered.
type Style int

const (
	Body Style = iota // ordinary text
	Head              // a small heading
	Fine              // a note, smaller and quieter
	Code              // a command or a path, in letters of one width
)

// Paragraph is one block of text in a Reader.
type Paragraph struct {
	Text  string
	Style Style
}

// reader is what a Control of the reader kind holds besides the rest.
type reader struct {
	paragraphs []Paragraph
	heights    []int // how tall each paragraph is, in pixels
	measured   bool
	total      int  // how tall all of it is
	offset     int  // how far down it has been scrolled, in pixels
	scrolling  bool // the pointer is holding the scroll bar
	held       int  // where on the handle the pointer took hold
}

// Reader is a box of text in paragraphs, which scrolls when the text is
// longer than the box: with the mouse wheel, the bar at its right and the
// arrow keys. Words too long for a line, as paths are, get broken.
func (w *Window) Reader(x, y, width, height int) *Control {
	c := w.add(kindReader, x, y, width, height, "", nil)
	c.reader = &reader{}
	return c
}

// Read replaces what a Reader shows and goes back to its top.
func (c *Control) Read(paragraphs ...Paragraph) {
	c.reader.paragraphs, c.reader.measured, c.reader.offset = paragraphs, false, 0
	c.redraw()
}

// Words returns everything a Reader shows as plain text, a paragraph to a
// line, for copying.
func (c *Control) Words() string {
	text := ""
	for _, p := range c.reader.paragraphs {
		text += p.Text + "\r\n"
	}
	return text
}

// lettering returns the font and colour of a style, and the space left
// above a paragraph in it.
func (w *Window) lettering(style Style) (font uintptr, colour Colour, above int) {
	switch style {
	case Head:
		return w.fonts.strong, theme.Ink, w.px(10)
	case Fine:
		return w.fonts.small, theme.Quiet, w.px(4)
	case Code:
		return w.fonts.code, theme.Ink, w.px(2)
	}
	return w.fonts.body, theme.Soft, w.px(2)
}

// The measures of a reader, in pixels: the space between its edge and its
// text at the sides and at top and bottom, and the width of the scroll bar.
func (c *Control) readerMeasures() (side, edge, bar int) {
	return c.w.px(14), c.w.px(10), c.w.px(14)
}

// layout measures the paragraphs for the width of the box.
func (c *Control) layout() {
	r := c.reader
	if r.measured {
		return
	}
	_, _, width, _ := c.box()
	side, _, bar := c.readerMeasures()
	r.heights, r.total = make([]int, len(r.paragraphs)), 0
	for i, p := range r.paragraphs {
		font, _, above := c.w.lettering(p.Style)
		if i == 0 {
			above = 0
		}
		r.heights[i] = c.w.measure(p.Text, font, width-2*side-bar, textWrap|textBreak)
		r.total += above + r.heights[i]
	}
	r.measured = true
}

// view returns how much of the text shows at once, in pixels.
func (c *Control) view() int {
	_, _, _, height := c.box()
	_, edge, _ := c.readerMeasures()
	return max(height-2*edge, 1)
}

// readerScroll shows the text from so many pixels down, as far as it goes.
func (c *Control) readerScroll(offset int) {
	c.layout()
	offset = max(0, min(offset, c.reader.total-c.view()))
	if offset != c.reader.offset {
		c.reader.offset = offset
		c.redraw()
	}
}

// readerThumb returns where the handle of the scroll bar is, from the top
// of its track, and how long it and the track are. length is zero when all
// the text fits and there is no bar.
func (c *Control) readerThumb() (offset, length, track int) {
	c.layout()
	r, view := c.reader, c.view()
	if r.total <= view {
		return 0, 0, 0
	}
	track = view
	length = max(track*view/r.total, c.w.px(24))
	offset = (track - length) * r.offset / (r.total - view)
	return offset, length, track
}

// readerDown handles a press of the mouse button on a reader.
func (c *Control) readerDown(px, py int) {
	x, y, width, _ := c.box()
	_, edge, bar := c.readerMeasures()
	offset, length, _ := c.readerThumb()
	if length == 0 || px < x+width-bar {
		return
	}
	r := c.reader
	r.scrolling, r.held = true, length/2
	if at := py - y - edge - offset; at >= 0 && at < length {
		r.held = at // taken by the handle itself: it stays under the pointer
	}
	c.readerDrag(py)
}

// readerDrag moves the text so the handle of the scroll bar follows the pointer.
func (c *Control) readerDrag(py int) {
	_, y, _, _ := c.box()
	_, edge, _ := c.readerMeasures()
	_, length, track := c.readerThumb()
	if track <= length {
		return
	}
	at := float64(py-y-edge-c.reader.held) / float64(track-length)
	c.readerScroll(int(math.Round(at * float64(c.reader.total-c.view()))))
}

// readerKey scrolls with the keyboard and reports whether the key was one
// it uses.
func (c *Control) readerKey(key uint32) bool {
	line, page := c.w.px(40), c.view()-c.w.px(20)
	switch key {
	case vkUp:
		c.readerScroll(c.reader.offset - line)
	case vkDown:
		c.readerScroll(c.reader.offset + line)
	case vkPrior:
		c.readerScroll(c.reader.offset - page)
	case vkNext:
		c.readerScroll(c.reader.offset + page)
	case vkHome:
		c.readerScroll(0)
	case vkEnd:
		c.readerScroll(math.MaxInt32)
	default:
		return false
	}
	return true
}

func (c *Control) drawReader(cv *Canvas) {
	w, r := c.w, c.reader
	x, y, width, height := c.box()
	side, edge, bar := c.readerMeasures()
	radius := w.pxf(9)
	cv.Round(x, y, width, height, radius, theme.Well)
	cv.Ring(x, y, width, height, radius, w.pxf(1), theme.WellEdge)
	c.layout()
	// Only the part of the text that is inside the box is drawn.
	before := cv.clipped()
	top, bottom := y+edge, y+height-edge
	if cv.Clip(max(x, before[0]), max(top, before[1]), min(x+width, before[2]), min(bottom, before[3])) {
		at := top - r.offset
		for i, p := range r.paragraphs {
			font, colour, above := w.lettering(p.Style)
			if i > 0 {
				at += above
			}
			if tall := r.heights[i]; at+tall > top && at < bottom {
				w.write(cv, p.Text, font, x+side, at, width-2*side-bar, tall, textWrap|textBreak, colour)
			}
			at += r.heights[i]
		}
	}
	cv.Clip(before[0], before[1], before[2], before[3])
	if offset, length, _ := c.readerThumb(); length > 0 {
		cv.Round(x+width-bar+w.px(3), y+edge+offset, bar-w.px(7), length, float64(bar-w.px(7))/2,
			pick(r.scrolling || w.hover == c, theme.SwitchEdge, theme.FieldEdge))
	}
}

// Copy puts text on the clipboard, and reports whether it could.
func (w *Window) Copy(text string) bool {
	units, err := syscall.UTF16FromString(text)
	if err != nil {
		return false
	}
	if ok, _, _ := user32.NewProc("OpenClipboard").Call(w.Handle); ok == 0 {
		return false
	}
	defer user32.NewProc("CloseClipboard").Call()
	user32.NewProc("EmptyClipboard").Call()
	const movable, unicodeText = 0x0002, 13
	size := uintptr(2 * len(units))
	memory, _, _ := kernel32.NewProc("GlobalAlloc").Call(movable, size)
	if memory == 0 {
		return false
	}
	locked, _, _ := kernel32.NewProc("GlobalLock").Call(memory)
	if locked == 0 {
		kernel32.NewProc("GlobalFree").Call(memory)
		return false
	}
	// The address comes from Windows as a number; this writes through it as
	// the pointer it is.
	copy(unsafe.Slice(*(**uint16)(unsafe.Pointer(&locked)), len(units)), units)
	kernel32.NewProc("GlobalUnlock").Call(memory)
	// From here the clipboard owns the memory.
	if handle, _, _ := user32.NewProc("SetClipboardData").Call(unicodeText, memory); handle == 0 {
		kernel32.NewProc("GlobalFree").Call(memory)
		return false
	}
	return true
}
