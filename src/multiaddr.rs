use Segment;

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct MultiAddr {
    segments: Vec<Segment>,
}

impl MultiAddr {
    pub fn new(segments: Vec<Segment>) -> MultiAddr {
        MultiAddr {
            segments: segments,
        }
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn split_off_last(mut self) -> Option<(MultiAddr, Segment)> {
        self.segments.pop().map(|tail| (self, tail))
    }
}
