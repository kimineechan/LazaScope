//go:build windows

package winui

import (
	"strings"
	"syscall"
	"unsafe"
)

// field is what a Control that takes typed text holds besides the rest.
type field struct {
	caret  int    // how many characters are before the place where typing goes
	whole  bool   // everything is selected, so typing replaces it
	secret bool   // the text is a secret, such as a key, and is shown as dots
	hint   string // shown faintly while the box is empty and not being typed in
}

// Hint sets the words an empty input box shows faintly, to say what it is for.
func (c *Control) Hint(text string) {
	if c.field != nil {
		c.field.hint = text
		c.redraw()
	}
}

// Secret makes an input box show a dot for each character typed into it,
// for a key or a password. What is typed cannot be copied back out.
func (c *Control) Secret() {
	if c.field != nil {
		c.field.secret = true
		c.redraw()
	}
}

// shown returns the text as the box shows it.
func (c *Control) shown() string {
	if c.field != nil && c.field.secret {
		return strings.Repeat("\u2022", len([]rune(c.text)))
	}
	return c.text
}

// Input is a box for one line of typed text. action runs when the text changes.
func (w *Window) Input(text string, x, y, width, height int, action func()) *Control {
	c := w.add(kindInput, x, y, width, height, text, action)
	c.field = &field{caret: len([]rune(text))}
	return c
}

// write replaces the text of an input box and puts the caret after it.
func (c *Control) retype(letters []rune, caret int) {
	c.text, c.field.caret, c.field.whole = string(letters), caret, false
	c.redraw()
	c.run()
}

// inputChar takes a typed character.
func (c *Control) inputChar(letter rune) {
	if letter < 32 || letter == 127 {
		return
	}
	letters, caret := []rune(c.text), c.field.caret
	if c.field.whole {
		letters, caret = nil, 0
	}
	letters = append(letters[:caret:caret], append([]rune{letter}, letters[caret:]...)...)
	c.retype(letters, caret+1)
}

// inputKey handles the keys that edit or move, and reports whether the key
// was one of them. Other keys are left to arrive as typed characters.
func (c *Control) inputKey(key, modifiers uint32) bool {
	letters, f := []rune(c.text), c.field
	switch {
	case modifiers&Ctrl != 0 && key == 'A':
		f.whole = len(letters) > 0
	case modifiers&Ctrl != 0 && key == 'V':
		for _, letter := range clipboard(c.w.Handle) {
			c.inputChar(letter)
		}
		return true
	case f.whole && (key == vkBack || key == vkDelete):
		c.retype(nil, 0)
		return true
	case key == vkBack && f.caret > 0:
		c.retype(append(letters[:f.caret-1:f.caret-1], letters[f.caret:]...), f.caret-1)
		return true
	case key == vkDelete && f.caret < len(letters):
		c.retype(append(letters[:f.caret:f.caret], letters[f.caret+1:]...), f.caret)
		return true
	case key == vkBack || key == vkDelete:
	case key == vkLeft:
		f.caret, f.whole = max(f.caret-1, 0), false
	case key == vkRight:
		f.caret, f.whole = min(f.caret+1, len(letters)), false
	case key == vkHome:
		f.caret, f.whole = 0, false
	case key == vkEnd:
		f.caret, f.whole = len(letters), false
	default:
		return false
	}
	c.redraw()
	return true
}

// clipboard returns the text on the clipboard, on one line.
func clipboard(window uintptr) string {
	const unicodeText = 13
	if ok, _, _ := user32.NewProc("OpenClipboard").Call(window); ok == 0 {
		return ""
	}
	defer user32.NewProc("CloseClipboard").Call()
	handle, _, _ := user32.NewProc("GetClipboardData").Call(unicodeText)
	if handle == 0 {
		return ""
	}
	locked, _, _ := kernel32.NewProc("GlobalLock").Call(handle)
	if locked == 0 {
		return ""
	}
	defer kernel32.NewProc("GlobalUnlock").Call(handle)
	// The address comes from Windows as a number; this reads it as the
	// pointer it is.
	text := *(**[1 << 16]uint16)(unsafe.Pointer(&locked))
	return strings.NewReplacer("\r", "", "\n", " ", "\t", " ").Replace(syscall.UTF16ToString(text[:]))
}

// span returns how wide some text is in the usual letters, in pixels.
func (w *Window) span(text string) int {
	if text == "" {
		return 0
	}
	var size extent
	units := wide(text)
	selectObject.Call(w.stencil.context, w.fonts.body)
	textExtent.Call(w.stencil.context, uintptr(unsafe.Pointer(&units[0])), uintptr(len(units)-1), uintptr(unsafe.Pointer(&size)))
	return int(size.Width)
}

// caretAt puts the caret of an input box where the pointer pressed.
func (c *Control) caretAt(px int) {
	x, _, _, _ := c.box()
	letters := []rune(c.shown())
	target := px - x - c.w.px(12) + c.slide()
	c.field.caret, c.field.whole = len(letters), false
	for i := range letters {
		if c.w.span(string(letters[:i+1]))-c.w.span(string(letters[i:i+1]))/2 > target {
			c.field.caret = i
			break
		}
	}
	c.redraw()
}

// slide is how far the text of an input box is moved left so that the
// caret stays in view when the text is wider than the box.
func (c *Control) slide() int {
	_, _, width, _ := c.box()
	room := width - 2*c.w.px(12)
	return max(c.w.span(string([]rune(c.shown())[:c.field.caret]))-room, 0)
}

func (c *Control) drawInput(cv *Canvas) {
	w := c.w
	x, y, width, height := c.box()
	radius, inset := w.pxf(9), w.px(12)
	lit := w.focus == c && w.active
	cv.Round(x, y, width, height, radius, pick(w.hover == c || lit, theme.FieldHover, theme.Field))
	cv.Ring(x, y, width, height, radius, w.pxf(1), pick(lit, theme.FieldLit, theme.FieldEdge))
	room, slide := width-2*inset, c.slide()
	// Only the part of the text that is inside the box is drawn.
	before := cv.clipped()
	cv.Clip(max(x+inset, before[0]), max(y, before[1]), min(x+inset+room, before[2]), min(y+height, before[3]))
	if c.field.whole && lit {
		cv.Round(x+inset-w.px(2), y+w.px(6), min(w.span(c.shown()), room)+w.px(4), height-w.px(12), w.pxf(4), theme.FieldLit.Thinned(0.5))
	}
	if c.text == "" && !lit && c.field.hint != "" {
		w.write(cv, c.field.hint, c.font, x+inset, y, room, height, textMiddle|textEllipsis, theme.Faint)
	}
	w.write(cv, c.shown(), c.font, x+inset-slide, y, w.span(c.shown())+w.px(4), height, textMiddle, pick(c.disabled, theme.Faint, theme.Ink))
	if lit && !c.field.whole {
		at := x + inset - slide + w.span(string([]rune(c.shown())[:c.field.caret]))
		cv.Fill(at, y+w.px(8), max(w.px(1), 1), height-w.px(16), theme.Ink)
	}
	cv.Clip(before[0], before[1], before[2], before[3])
}

// Picture is a square that shows an icon file.
func (w *Window) Picture(x, y, size int) *Control {
	return w.add(kindPicture, x, y, size, size, "", nil)
}

// ShowIcon shows the icon in a file in a picture, or nothing for "".
//
// Windows draws icons without saying how see-through each pixel is, so the
// icon is drawn twice, on black and on white. Where the two results agree
// the pixel is solid; where they differ, the difference is how much shows
// through.
func (c *Control) ShowIcon(path string) {
	w := c.w
	c.picture = nil
	c.redraw()
	if path == "" {
		return
	}
	_, _, size, _ := c.box()
	size = min(size, w.stencil.width, w.stencil.height)
	const icon, fromFile = 1, 0x10
	handle, _, _ := loadImage.Call(0, uintptr(unsafe.Pointer(ptr(path))), icon, uintptr(size), uintptr(size), fromFile)
	if handle == 0 {
		return
	}
	defer user32.NewProc("DestroyIcon").Call(handle)
	var shots [2][]uint32
	for i, ground := range []uint32{0x000000, 0xFFFFFF} {
		for row := 0; row < size; row++ {
			line := w.stencil.pix[row*w.stencil.width:][:size]
			for j := range line {
				line[j] = ground
			}
		}
		const normal = 3
		user32.NewProc("DrawIconEx").Call(w.stencil.context, 0, 0, handle, uintptr(size), uintptr(size), 0, 0, normal)
		gdiFlush.Call()
		shots[i] = make([]uint32, size*size)
		for row := 0; row < size; row++ {
			copy(shots[i][row*size:], w.stencil.pix[row*w.stencil.width:][:size])
		}
	}
	c.picture = make([]uint32, size*size)
	for i, black := range shots[0] {
		white := shots[1][i]
		// On black a pixel shows its colour times its opacity; on white it
		// shows that plus what shows through.
		alpha := 255 - min((white>>8&0xFF)-(black>>8&0xFF), 255)
		c.picture[i] = alpha<<24 | black&0xFFFFFF
	}
}

func (c *Control) drawPicture(cv *Canvas) {
	x, y, size, _ := c.box()
	cv.Round(x-c.w.px(6), y-c.w.px(6), size+c.w.px(12), size+c.w.px(12), c.w.pxf(10), theme.Well)
	cv.Ring(x-c.w.px(6), y-c.w.px(6), size+c.w.px(12), size+c.w.px(12), c.w.pxf(10), c.w.pxf(1), theme.WellEdge)
	if len(c.picture) == size*size {
		cv.Paint(x, y, c.picture, size, size)
	}
}
