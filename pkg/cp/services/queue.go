// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import "time"

// ScanQueue is a simple bounded channel-based queue for scan tasks.
type ScanQueue struct {
	tasks chan ScanTask
}

func NewScanQueue(size int) *ScanQueue {
	if size <= 0 {
		size = 1024
	}
	return &ScanQueue{tasks: make(chan ScanTask, size)}
}

// Enqueue enqueues a scan task; returns false if the queue is full.
func (q *ScanQueue) Enqueue(task ScanTask) bool {
	if q == nil {
		return false
	}
	select {
	case q.tasks <- task:
		return true
	default:
		return false
	}
}

// Dequeue retrieves a task, waiting up to timeout.
func (q *ScanQueue) Dequeue(timeout time.Duration) (ScanTask, bool) {
	if q == nil {
		return ScanTask{}, false
	}
	select {
	case t := <-q.tasks:
		return t, true
	case <-time.After(timeout):
		return ScanTask{}, false
	}
}

// Len returns the number of pending tasks.
func (q *ScanQueue) Len() int {
	if q == nil || q.tasks == nil {
		return 0
	}
	return len(q.tasks)
}
