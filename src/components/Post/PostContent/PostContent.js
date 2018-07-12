import React from 'react';

import './PostContent.css'
import {Classes} from '@blueprintjs/core'
import MathRenderer from './MathRenderer/MathRenderer';

const loremIpsum = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ac pharetra est, quis venenatis dui.' +
    ' Etiam eros purus, accumsan sed risus eget, pulvinar lobortis odio. Integer mattis a sem vel molestie. Quisque' +
    ' gravida justo tellus, nec maximus arcu lobortis vitae. Phasellus tempus leo ac tortor aliquet fringilla. Morbi ' +
    'semper lorem vitae quam sagittis, et consequat dui efficitur. Pellentesque eros arcu, interdum at dui a, semper' +
    ' varius velit. Donec arcu justo, sodales semper feugiat in, fringilla pharetra tortor. Curabitur ut quam quam. ' +
    'Vivamus rhoncus augue sit amet arcu pulvinar ultricies. Vestibulum eu dolor vel neque fringilla vulputate a sed' +
    ' lorem. Nulla bibendum dui vitae dapibus commodo.';

class PostContent extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            loading: false
        };
        this.onRenderFinish = this.onRenderFinish.bind(this);
    }


    genLoremIpsum() {
        let paragraphs = [];
        for (let i = 0; i < 10; i++) {
            paragraphs.push(<p key={i} className={Classes.SKELETON}>{loremIpsum + loremIpsum}<br/></p>);
        }
        return paragraphs.map(e => e);
    }

    getContentBlock(input) {
        if (this.state.loading || !input) {
            return this.genLoremIpsum();

        }
        return (
            <span className={this.state.loading ? Classes.SKELETON : Classes.RUNNING_TEXT}>
                {this.state.loading ? this.genLoremIpsum() : ''}
                <MathRenderer onRenderFinish={this.onRenderFinish} source={input}/>
            </span>
        );
    }

    onRenderFinish() {
        this.setState({
            loading: false
        });
    }

    render() {
        return (
            <div className={'content ' + this.props.className}>
                {this.getContentBlock(this.props.content)}
            </div>
        );
    }
}

export default PostContent;