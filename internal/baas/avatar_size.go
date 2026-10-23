package baas

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"net/http"
	"strconv"
	"sync"
)

// The friends module asks the cdn-image host for /1/<id>?width=N&height=N
// (128 in the friend-code search) and draws "?" when what comes back is not
// the size it asked for. Nintendo's CDN scales on request; so does this.
// The answer is always a baseline JPEG -- image/jpeg writes nothing else --
// because a progressive one breaks the Switch's decoder (2206-1017).

// maxAvatarSide bounds a requested side: the console asks for 128 or 256,
// and nothing should make this server allocate a poster.
const maxAvatarSide = 1024

// avatarSize reads the requested size. ok is false when the request names
// none (the default answer, unchanged) or one that is not a sane size.
func avatarSize(r *http.Request) (w, h int, ok bool) {
	q := r.URL.Query()
	ws, hs := q.Get("width"), q.Get("height")
	if ws == "" && hs == "" {
		return 0, 0, false
	}
	if ws == "" {
		ws = hs
	}
	if hs == "" {
		hs = ws
	}
	w, errW := strconv.Atoi(ws)
	h, errH := strconv.Atoi(hs)
	if errW != nil || errH != nil || w < 1 || h < 1 || w > maxAvatarSide || h > maxAvatarSide {
		return 0, 0, false
	}
	return w, h, true
}

var resizedAvatars = struct {
	sync.Mutex
	m map[string][]byte
}{m: map[string][]byte{}}

// resizedAvatarJPEG scales a JPEG to w×h (centre-cropped to that aspect) and
// re-encodes it as a baseline JPEG. Anything that will not decode is returned
// as it came: the old answer beats no answer.
func resizedAvatarJPEG(img []byte, w, h int) []byte {
	sum := sha256.Sum256(img)
	key := fmt.Sprintf("%x/%dx%d", sum[:16], w, h)
	resizedAvatars.Lock()
	out, hit := resizedAvatars.m[key]
	resizedAvatars.Unlock()
	if hit {
		return out
	}
	src, err := jpeg.Decode(bytes.NewReader(img))
	if err != nil {
		return img
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, scaleBox(src, w, h), &jpeg.Options{Quality: 90}); err != nil {
		return img
	}
	out = buf.Bytes()
	resizedAvatars.Lock()
	if len(resizedAvatars.m) >= 512 { // a few hundred friends' pictures; then start over
		resizedAvatars.m = map[string][]byte{}
	}
	resizedAvatars.m[key] = out
	resizedAvatars.Unlock()
	return out
}

// scaleBox centre-crops src to the w:h aspect and area-averages it down to
// w×h (each destination pixel is the mean of the source pixels it covers;
// enlarging degrades to nearest neighbour).
func scaleBox(src image.Image, w, h int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	// Crop to the target aspect so a non-square picture is not squashed.
	if sw*h > sh*w {
		cw := sh * w / h
		b.Min.X += (sw - cw) / 2
		b.Max.X = b.Min.X + cw
	} else if sw*h < sh*w {
		ch := sw * h / w
		b.Min.Y += (sh - ch) / 2
		b.Max.Y = b.Min.Y + ch
	}
	sw, sh = max(1, b.Dx()), max(1, b.Dy())
	rgba := image.NewRGBA(image.Rect(0, 0, sw, sh))
	draw.Draw(rgba, rgba.Rect, src, b.Min, draw.Src)

	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		y0, y1 := y*sh/h, (y+1)*sh/h
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < w; x++ {
			x0, x1 := x*sw/w, (x+1)*sw/w
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, n uint32
			for sy := y0; sy < y1; sy++ {
				row := rgba.Pix[sy*rgba.Stride:]
				for sx := x0; sx < x1; sx++ {
					p := row[sx*4:]
					r, g, bl, n = r+uint32(p[0]), g+uint32(p[1]), bl+uint32(p[2]), n+1
				}
			}
			d := dst.Pix[y*dst.Stride+x*4:]
			d[0], d[1], d[2], d[3] = uint8((r+n/2)/n), uint8((g+n/2)/n), uint8((bl+n/2)/n), 255
		}
	}
	return dst
}

// writeAvatarJPEG answers a cdn-image picture request: the stored JPEG as it
// is, or scaled when the request names a size.
func writeAvatarJPEG(w http.ResponseWriter, r *http.Request, img []byte, cacheControl string) {
	if sw, sh, ok := avatarSize(r); ok {
		img = resizedAvatarJPEG(img, sw, sh)
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", cacheControl)
	w.Write(img)
}
