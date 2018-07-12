import React from 'react';

import './PostSnippet.css'
import {Text} from '@blueprintjs/core';

import PostHeader from '../../Post/PostHeader/PostHeader';
import {Link} from 'react-router-dom';

class PostSnippet extends React.Component {
    getContentBlock() {
        if (!this.props.post.overview) {
            return (<Text className={'bp3-skeleton'}>
                {'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ac pharetra est, quis venenatis dui.' +
                ' Etiam eros purus, accumsan sed risus eget, pulvinar lobortis odio. Integer mattis a sem vel molestie. Quisque'}
            </Text>)
        }
        return (
            <Text>
                {this.props.post.overview}
            </Text>
        );
    }

    render() {
        return (
            <div className={'snippet-container ' + this.props.className ? this.props.className : ''}>
                <Link to={'/posts/' + this.props.post.slug}>
                    <PostHeader tags={this.props.post.tags} title={this.props.post.title}/>
                </Link>
                {this.getContentBlock()}
            </div>
        )
    }
}

export default PostSnippet;