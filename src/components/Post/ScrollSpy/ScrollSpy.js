import React from 'react';

import styles from './ScrollSpy.module.css'
import type {Identifier} from "../../../data/resource/identifier";

interface ScrollSpyProps {
    root: React.Ref;
    postId: Identifier;
}

interface ScrollSpyState {
    headings: Array<{ name: string, position: number, level: number }>,
    current?: { name: string, position: number, level: number },
}

class ScrollSpy extends React.Component<ScrollSpyProps, ScrollSpyState> {
    scrollListener = function () {
        const cur = this.props.root.current;

        const headings = []

        function positionHeaders(tagName, level) {
            cur.querySelectorAll(tagName).forEach((val) => {
                headings.push({name: val.innerText, position: val.offsetTop - 20, level: level})
            })
        }

        positionHeaders('h1', 1)
        positionHeaders('h2', 2)
        positionHeaders('h3', 3)

        headings.sort((a, b) => a.position - b.position)

        const scroll = window.scrollY
        let curObj = undefined

        headings.forEach((val, index) => {
            // headings is sorted in ascending order
            if (val.position < scroll) {
                curObj = val
            }
        })

        this.setState({headings: headings, current: curObj})
    }

    constructor(props) {
        super(props);

        this.state = {
            headings: [],
            current: undefined,
        }

        this.scrollListener = this.scrollListener.bind(this);

        window.addEventListener('scroll', this.scrollListener)
    }

    scrollTo(pos) {
        window.scrollTo({
            top: pos + 5,
            behavior: 'smooth'
        })
        this.scrollListener()
    }

    componentWillUnmount(): void {
        window.removeEventListener('scroll', this.scrollListener)
    }

    componentDidUpdate(prevProps: Readonly<ScrollSpyProps>, prevState: Readonly<ScrollSpyState>, snapshot: SS): void {
        if (prevProps.postId !== this.props.postId && this.props.root && this.props.root.current) {
            this.scrollListener()
        }
    }

    render() {
        return (
            <div className={styles.scrollSpy}>
                {
                    this.state.headings.map((value => {
                        if (value === this.state.current) {
                            return (
                                <div key={value.position} onClick={() => this.scrollTo(value.position)}
                                     className={styles.selected + ' ' + styles[`level-${value.level}`]}>
                                    {value.name}
                                </div>)
                        } else {
                            return (
                                <div key={value.position} onClick={() => this.scrollTo(value.position)}
                                     className={styles.value + ' ' + styles[`level-${value.level}`]}>
                                    {value.name}
                                </div>)
                        }
                    }))
                }
            </div>
        )

    }
}

export default ScrollSpy;