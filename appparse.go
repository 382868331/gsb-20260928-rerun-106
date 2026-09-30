package netforensics

import "bytes"

func ParseApplicationMessages(result StreamResult, delimiter []byte, maxMessageBytes int) ([]ApplicationMessage, error) {
	if len(delimiter) == 0 {
		return nil, ErrInvalidAddress
	}
	if maxMessageBytes < 0 {
		return nil, ErrApplicationMessageBudget
	}
	messages := make([]ApplicationMessage, 0)
	var pending []byte
	pendingStart := int64(-1)
	seenData := false
	flush := func(blocked *IncompleteRange, resetOffset int64) {
		if len(pending) == 0 {
			if resetOffset >= 0 {
				pendingStart = -1
			}
			return
		}
		data := append([]byte(nil), pending...)
		endOffset := pendingStart + int64(len(pending))
		messages = append(messages, ApplicationMessage{
			Data:         data,
			StartOffset:  pendingStart,
			EndOffset:    endOffset,
			Complete:     false,
			BlockedRange: blocked,
		})
		pending = nil
		pendingStart = -1
	}
	for _, block := range result.Blocks {
		if block.Kind == BlockGap || block.Kind == BlockAmbiguous {
			if len(pending) == 0 {
				messages = append(messages, ApplicationMessage{
					StartOffset:  block.StartOffset,
					EndOffset:    block.StartOffset,
					Complete:     false,
					BlockedRange: &IncompleteRange{Start: block.StartOffset, End: block.StartOffset + int64(block.Length), Reason: blockKindReason(block.Kind)},
				})
			}
			blocked := IncompleteRange{Start: block.StartOffset, End: block.StartOffset + int64(block.Length), Reason: blockKindReason(block.Kind)}
			flush(&blocked, blocked.End)
			continue
		}
		if block.Kind != BlockData {
			continue
		}
		if pendingStart < 0 {
			pendingStart = block.StartOffset
		}
		searchStart := len(pending) - (len(delimiter) - 1)
		if searchStart < 0 {
			searchStart = 0
		}
		pending = append(pending, block.Data...)
		seenData = true
		if maxMessageBytes > 0 && len(pending) > maxMessageBytes+len(delimiter) {
			return messages, ErrApplicationMessageBudget
		}
		for {
			idx := bytes.Index(pending[searchStart:], delimiter)
			if idx < 0 {
				break
			}
			idx += searchStart
			if maxMessageBytes > 0 && idx > maxMessageBytes {
				return messages, ErrApplicationMessageBudget
			}
			messageEnd := idx + len(delimiter)
			messages = append(messages, ApplicationMessage{
				Data:        append([]byte(nil), pending[:idx]...),
				StartOffset: pendingStart,
				EndOffset:   pendingStart + int64(messageEnd),
				Complete:    true,
			})
			pending = append([]byte(nil), pending[messageEnd:]...)
			pendingStart = -1
			searchStart = 0
		}
		if pendingStart < 0 && len(pending) > 0 {
			pendingStart = block.StartOffset + int64(len(block.Data)-len(pending))
		}
	}
	flush(nil, -1)
	if seenData {
		for i := range messages {
			if !messages[i].Complete && messages[i].BlockedRange == nil {
				messages[i].Complete = result.Closed
			}
		}
	}
	return messages, nil
}

func blockKindReason(kind BlockKind) string {
	if kind == BlockAmbiguous {
		return "ambiguous overlapping data"
	}
	return "missing data"
}
